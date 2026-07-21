use std::future::Future;
use std::pin::Pin;
use std::sync::Arc;
use std::task::{Context, Poll};

use axum::body::Body;
use axum::http::{Request, Response, StatusCode};
use axum::response::IntoResponse;
use tower::{Layer, Service};

use aauth::ResourceAccessContext;
use aauth::ResourceAccessMode;
use aauth::ResourceAccessService;
use aauth::jwt::VerifiedToken;
use aauth::metadata::MetadataFetcher;
use aauth::protocol::AAuthChallenge;
use aauth::protocol::build_aauth_requirement;
use aauth::resource::keys::ResourceTokenSigner;
use aauth::resource::{
    ResourceInteractionContext, ResourceInteractionProvider, ResourceTokenOptions,
    create_resource_token,
};
use aauth::resource_verify::{
    VerifyTokenOptions, resolve_resource_token_audience, verify_auth_token_binding, verify_token,
};
use aauth::signature::{SignatureVerifyOptions, verify_request_signature_with_options};

use crate::AauthResponse;

#[derive(Clone)]
pub struct ResourceAuthLayer<RAS>
where
    RAS: ResourceAccessService,
{
    pub fetcher: Arc<dyn MetadataFetcher>,
    pub resource_url: String,
    pub mode: ResourceAccessMode<RAS>,
    pub resource_token_signer: Arc<dyn ResourceTokenSigner>,
    pub interaction_provider: Option<Arc<dyn ResourceInteractionProvider>>,
}

impl<RAS> ResourceAuthLayer<RAS>
where
    RAS: ResourceAccessService,
{
    pub fn new(
        fetcher: Arc<dyn MetadataFetcher>,
        resource_url: impl Into<String>,
        mode: ResourceAccessMode<RAS>,
        resource_token_signer: Arc<dyn ResourceTokenSigner>,
    ) -> Self {
        Self {
            fetcher,
            resource_url: resource_url.into(),
            mode,
            resource_token_signer,
            interaction_provider: None,
        }
    }

    pub fn with_interaction_provider(
        mut self,
        provider: Arc<dyn ResourceInteractionProvider>,
    ) -> Self {
        self.interaction_provider = Some(provider);
        self
    }
}

impl<S, RAS> Layer<S> for ResourceAuthLayer<RAS>
where
    RAS: ResourceAccessService,
{
    type Service = ResourceAuthService<S, RAS>;

    fn layer(&self, inner: S) -> Self::Service {
        ResourceAuthService {
            inner,
            fetcher: Arc::clone(&self.fetcher),
            resource_url: self.resource_url.clone(),
            mode: self.mode.clone(),
            resource_token_signer: Arc::clone(&self.resource_token_signer),
            interaction_provider: self.interaction_provider.clone(),
        }
    }
}

#[derive(Clone)]
pub struct ResourceAuthService<S, RAS>
where
    RAS: ResourceAccessService,
{
    inner: S,
    fetcher: Arc<dyn MetadataFetcher>,
    resource_url: String,
    mode: ResourceAccessMode<RAS>,
    resource_token_signer: Arc<dyn ResourceTokenSigner>,
    interaction_provider: Option<Arc<dyn ResourceInteractionProvider>>,
}

impl<S, B, RAS> Service<Request<B>> for ResourceAuthService<S, RAS>
where
    S: Service<Request<B>, Response = Response<Body>> + Clone + Send + 'static,
    S::Future: Send + 'static,
    S::Error: std::fmt::Display + Send + 'static,
    B: Send + 'static,
    RAS: ResourceAccessService + Clone + Send + Sync + 'static,
{
    type Response = Response<Body>;
    type Error = S::Error;
    type Future = Pin<Box<dyn Future<Output = Result<Self::Response, Self::Error>> + Send>>;

    fn poll_ready(&mut self, cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        self.inner.poll_ready(cx)
    }

    fn call(&mut self, mut req: Request<B>) -> Self::Future {
        let fetcher = Arc::clone(&self.fetcher);
        let resource_url = self.resource_url.clone();
        let mode = self.mode.clone();
        let resource_token_signer = Arc::clone(&self.resource_token_signer);
        let interaction_provider = self.interaction_provider.clone();
        let mut inner = self.inner.clone();

        Box::pin(async move {
            let (method, authority, path) = request_signature_parts(&req);

            let opaque_retry = matches!(&mode, ResourceAccessMode::ResourceManaged { .. })
                && extract_aauth_access(req.headers()).is_some();

            let sig_options = if opaque_retry {
                SignatureVerifyOptions {
                    require_authorization: true,
                    ..SignatureVerifyOptions::default()
                }
            } else {
                SignatureVerifyOptions::default()
            };

            let verified_sig = match verify_request_signature_with_options(
                &method,
                &authority,
                &path,
                req.headers(),
                &sig_options,
            ) {
                Ok(v) => v,
                Err(e) => return Ok(unauthorized_err(e)),
            };

            if let ResourceAccessMode::ResourceManaged { service } = &mode {
                if let Some(opaque_token) = extract_aauth_access(req.headers()) {
                    let agent_id = agent_sub_from_jwt(&verified_sig.jwt);
                    if service.validate_opaque(&opaque_token, &agent_id) {
                        if let Ok(VerifiedToken::Agent(agent)) =
                            VerifiedToken::decode_unverified(&verified_sig.jwt)
                        {
                            req.extensions_mut().insert(VerifiedToken::Agent(agent));
                            return inner.call(req).await;
                        }
                    }
                    return Ok(unauthorized_message("invalid opaque access token"));
                }
            }

            let verified = match verify_token(VerifyTokenOptions {
                jwt: verified_sig.jwt.clone(),
                http_signature_thumbprint: verified_sig.thumbprint.clone(),
                fetcher: Arc::clone(&fetcher),
            })
            .await
            {
                Ok(v) => v,
                Err(e) => return Ok(unauthorized_err(e)),
            };

            if let VerifiedToken::Auth(ref auth) = verified {
                if let Err(e) = verify_auth_token_binding(auth, &resource_url) {
                    return Ok(unauthorized_err(e));
                }
            }

            match (&mode, &verified) {
                (ResourceAccessMode::IdentityBased, _) => {
                    req.extensions_mut().insert(verified);
                    inner.call(req).await
                }
                (
                    ResourceAccessMode::PsAsserted {
                        require_auth_token: true,
                        access_server_url,
                        person_server_fallback,
                    },
                    VerifiedToken::Agent(agent),
                ) => {
                    let audience = match resolve_resource_token_audience(
                        agent,
                        access_server_url.as_deref(),
                        person_server_fallback.as_deref(),
                    ) {
                        Ok(aud) => aud,
                        Err(e) => {
                            return Ok(unauthorized_message(e.to_string()));
                        }
                    };

                    let interaction = interaction_provider.as_ref().and_then(|provider| {
                        provider.interaction_for(&ResourceInteractionContext {
                            resource_url: resource_url.clone(),
                            agent: agent.clone(),
                            agent_jkt: verified_sig.thumbprint.clone(),
                        })
                    });

                    let resource_token = match create_resource_token(
                        ResourceTokenOptions {
                            resource: resource_url,
                            audience,
                            agent: agent.identifier().to_string(),
                            agent_jkt: verified_sig.thumbprint,
                            scope: None,
                            mission: None,
                            lifetime: None,
                            interaction,
                        },
                        resource_token_signer.as_ref(),
                    )
                    .await
                    {
                        Ok(token) => token,
                        Err(e) => return Ok(unauthorized_err(e)),
                    };

                    let header = match build_aauth_requirement(&AAuthChallenge::AuthToken {
                        resource_token: resource_token.clone(),
                    }) {
                        Ok(h) => h,
                        Err(e) => return Ok(unauthorized_err(e)),
                    };

                    Ok(Response::builder()
                        .status(StatusCode::UNAUTHORIZED)
                        .header("AAuth-Requirement", header)
                        .body(Body::from("Auth token required"))
                        .expect("valid response"))
                }
                (ResourceAccessMode::PsAsserted { .. }, _) => {
                    req.extensions_mut().insert(verified);
                    inner.call(req).await
                }
                (ResourceAccessMode::ResourceManaged { service }, VerifiedToken::Agent(agent)) => {
                    let ctx = ResourceAccessContext {
                        resource_url: resource_url.clone(),
                        agent_claims: agent.clone(),
                        scope: None,
                    };

                    match service.consent_for_agent(ctx).await {
                        Ok(outcome) => Ok(AauthResponse(outcome).into_response()),
                        Err(e) => Ok(crate::InternalServiceError::from(e).into_response()),
                    }
                }
                (ResourceAccessMode::ResourceManaged { .. }, VerifiedToken::Auth(_)) => {
                    req.extensions_mut().insert(verified);
                    inner.call(req).await
                }
            }
        })
    }
}

fn agent_sub_from_jwt(jwt: &str) -> String {
    VerifiedToken::decode_unverified(jwt)
        .ok()
        .and_then(|t| t.agent_identifier().map(str::to_string))
        .unwrap_or_default()
}

fn extract_aauth_access(headers: &axum::http::HeaderMap) -> Option<String> {
    let value = headers.get("authorization").and_then(|v| v.to_str().ok())?;
    let rest = value.strip_prefix("AAuth ")?;
    if rest.is_empty() {
        return None;
    }
    Some(rest.to_string())
}

fn request_signature_parts<B>(req: &Request<B>) -> (String, String, String) {
    let method = req.method().as_str().to_string();
    let uri = req.uri();
    let authority = req
        .headers()
        .get("host")
        .and_then(|h| h.to_str().ok())
        .map(str::to_string)
        .unwrap_or_else(|| {
            uri.host()
                .map(|host| match uri.port_u16() {
                    Some(port) => format!("{host}:{port}"),
                    None => host.to_string(),
                })
                .unwrap_or_default()
        });
    let path = uri.path().to_string();
    (method, authority, path)
}

fn unauthorized_err(err: impl Into<aauth::AAuthError>) -> Response<Body> {
    let err = err.into();
    if let Some((status, protocol)) = aauth::IntoAauthProtocol::into_aauth_protocol(err) {
        let status = StatusCode::from_u16(status).unwrap_or(StatusCode::UNAUTHORIZED);
        return Response::builder()
            .status(status)
            .header("content-type", "application/json")
            .body(Body::from(
                serde_json::to_vec(&protocol).unwrap_or_default(),
            ))
            .expect("valid response");
    }
    Response::builder()
        .status(StatusCode::UNAUTHORIZED)
        .header("content-type", "application/json")
        .body(Body::from(
            serde_json::to_vec(&aauth::protocol::AAuthProtocolError::with_description(
                aauth::protocol::AAuthErrorCode::InvalidSignature,
                "unauthorized",
            ))
            .unwrap_or_default(),
        ))
        .expect("valid response")
}

fn unauthorized_message(message: impl Into<String>) -> Response<Body> {
    Response::builder()
        .status(StatusCode::UNAUTHORIZED)
        .header("content-type", "application/json")
        .body(Body::from(
            serde_json::to_vec(&aauth::protocol::AAuthProtocolError::with_description(
                aauth::protocol::AAuthErrorCode::InvalidRequest,
                message.into(),
            ))
            .unwrap_or_default(),
        ))
        .expect("valid response")
}
