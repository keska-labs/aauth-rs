use std::future::Future;
use std::pin::Pin;
use std::task::{Context, Poll};

use axum::body::Body;
use axum::http::header::{AUTHORIZATION, CONTENT_TYPE, HOST};
use axum::http::{Request, Response, StatusCode};
use axum::response::IntoResponse;
use tower::{Layer, Service};

use aauth::ResourceAccessContext;
use aauth::ResourceAccessMode;
use aauth::ResourceAccessService;
use aauth::jwt::ParsedToken;
use aauth::metadata::MetadataFetcher;
use aauth::protocol::{AAUTH_REQUIREMENT, AAuthChallenge};
use aauth::resource::keys::ResourceTokenSigner;
use aauth::resource::{
    NoResourceInteraction, ResourceInteractionContext, ResourceInteractionProvider,
    ResourceTokenOptions,
};
use aauth::resource_verify::{
    VerifyTokenOptions, resolve_resource_token_audience, verify_auth_token_binding, verify_token,
};
use aauth::signature::{SignatureVerifyOptions, verify_request_signature_with_options};

use crate::AauthResponse;

#[derive(Clone)]
pub struct ResourceAuthLayer<RAS, F, T, I = NoResourceInteraction>
where
    RAS: ResourceAccessService,
    F: MetadataFetcher,
    T: ResourceTokenSigner,
    I: ResourceInteractionProvider,
{
    pub fetcher: F,
    pub resource_url: String,
    pub mode: ResourceAccessMode<RAS>,
    pub resource_token_signer: T,
    pub interaction_provider: I,
}

impl<RAS, F, T> ResourceAuthLayer<RAS, F, T, NoResourceInteraction>
where
    RAS: ResourceAccessService,
    F: MetadataFetcher,
    T: ResourceTokenSigner,
{
    pub fn new(
        fetcher: F,
        resource_url: impl Into<String>,
        mode: ResourceAccessMode<RAS>,
        resource_token_signer: T,
    ) -> Self {
        Self {
            fetcher,
            resource_url: resource_url.into(),
            mode,
            resource_token_signer,
            interaction_provider: NoResourceInteraction,
        }
    }
}

impl<RAS, F, T, I> ResourceAuthLayer<RAS, F, T, I>
where
    RAS: ResourceAccessService,
    F: MetadataFetcher,
    T: ResourceTokenSigner,
    I: ResourceInteractionProvider,
{
    pub fn with_interaction_provider<I2: ResourceInteractionProvider>(
        self,
        provider: I2,
    ) -> ResourceAuthLayer<RAS, F, T, I2> {
        ResourceAuthLayer {
            fetcher: self.fetcher,
            resource_url: self.resource_url,
            mode: self.mode,
            resource_token_signer: self.resource_token_signer,
            interaction_provider: provider,
        }
    }
}

impl<S, RAS, F, T, I> Layer<S> for ResourceAuthLayer<RAS, F, T, I>
where
    RAS: ResourceAccessService,
    F: MetadataFetcher + Clone,
    T: ResourceTokenSigner + Clone,
    I: ResourceInteractionProvider + Clone,
{
    type Service = ResourceAuthService<S, RAS, F, T, I>;

    fn layer(&self, inner: S) -> Self::Service {
        ResourceAuthService {
            inner,
            fetcher: self.fetcher.clone(),
            resource_url: self.resource_url.clone(),
            mode: self.mode.clone(),
            resource_token_signer: self.resource_token_signer.clone(),
            interaction_provider: self.interaction_provider.clone(),
        }
    }
}

#[derive(Clone)]
pub struct ResourceAuthService<S, RAS, F, T, I = NoResourceInteraction>
where
    RAS: ResourceAccessService,
    F: MetadataFetcher,
    T: ResourceTokenSigner,
    I: ResourceInteractionProvider,
{
    inner: S,
    fetcher: F,
    resource_url: String,
    mode: ResourceAccessMode<RAS>,
    resource_token_signer: T,
    interaction_provider: I,
}

impl<S, B, RAS, F, T, I> Service<Request<B>> for ResourceAuthService<S, RAS, F, T, I>
where
    S: Service<Request<B>, Response = Response<Body>> + Clone + Send + 'static,
    S::Future: Send + 'static,
    S::Error: std::fmt::Display + Send + 'static,
    B: Send + 'static,
    RAS: ResourceAccessService + Clone + Send + Sync + 'static,
    F: MetadataFetcher + Clone + 'static,
    T: ResourceTokenSigner + Clone + 'static,
    I: ResourceInteractionProvider + Clone + 'static,
{
    type Response = Response<Body>;
    type Error = S::Error;
    type Future = Pin<Box<dyn Future<Output = Result<Self::Response, Self::Error>> + Send>>;

    fn poll_ready(&mut self, cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        self.inner.poll_ready(cx)
    }

    fn call(&mut self, mut req: Request<B>) -> Self::Future {
        let fetcher = self.fetcher.clone();
        let resource_url = self.resource_url.clone();
        let mode = self.mode.clone();
        let resource_token_signer = self.resource_token_signer.clone();
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
                        if let Ok(ParsedToken::Agent(agent)) = ParsedToken::parse(&verified_sig.jwt)
                        {
                            req.extensions_mut().insert(ParsedToken::Agent(agent));
                            return inner.call(req).await;
                        }
                    }
                    return Ok(unauthorized_message("invalid opaque access token"));
                }
            }

            let verified = match verify_token(VerifyTokenOptions {
                jwt: verified_sig.jwt.clone(),
                http_signature_thumbprint: verified_sig.thumbprint.clone(),
                fetcher: &fetcher,
            })
            .await
            {
                Ok(v) => v,
                Err(e) => return Ok(unauthorized_err(e)),
            };

            if let ParsedToken::Auth(ref auth) = verified {
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
                    ParsedToken::Agent(agent),
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

                    let interaction =
                        interaction_provider.interaction_for(&ResourceInteractionContext {
                            resource_url: resource_url.clone(),
                            agent: agent.clone(),
                            agent_jkt: verified_sig.thumbprint.clone(),
                        });

                    let resource_token = match (ResourceTokenOptions {
                        resource: resource_url,
                        audience,
                        agent: agent.identifier().to_string(),
                        agent_jkt: verified_sig.thumbprint,
                        scope: None,
                        mission: None,
                        lifetime: None,
                        interaction,
                    })
                    .sign(&resource_token_signer)
                    .await
                    {
                        Ok(token) => token,
                        Err(e) => return Ok(unauthorized_err(e)),
                    };

                    let header = AAuthChallenge::AuthToken {
                        resource_token: resource_token.clone(),
                    }
                    .to_header();

                    Ok(Response::builder()
                        .status(StatusCode::UNAUTHORIZED)
                        .header(AAUTH_REQUIREMENT, header)
                        .body(Body::from("Auth token required"))
                        .expect("valid response"))
                }
                (ResourceAccessMode::PsAsserted { .. }, _) => {
                    req.extensions_mut().insert(verified);
                    inner.call(req).await
                }
                (ResourceAccessMode::ResourceManaged { service }, ParsedToken::Agent(agent)) => {
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
                (ResourceAccessMode::ResourceManaged { .. }, ParsedToken::Auth(_)) => {
                    req.extensions_mut().insert(verified);
                    inner.call(req).await
                }
                (ResourceAccessMode::ResourceManaged { .. }, ParsedToken::Resource(_)) => {
                    Ok(unauthorized_message("unexpected resource token"))
                }
            }
        })
    }
}

fn agent_sub_from_jwt(jwt: &str) -> String {
    ParsedToken::parse(jwt)
        .ok()
        .and_then(|t| t.agent_identifier().map(str::to_string))
        .unwrap_or_default()
}

fn extract_aauth_access(headers: &axum::http::HeaderMap) -> Option<String> {
    let value = headers.get(AUTHORIZATION).and_then(|v| v.to_str().ok())?;
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
        .get(HOST)
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
            .header(CONTENT_TYPE, "application/json")
            .body(Body::from(
                serde_json::to_vec(&protocol).unwrap_or_default(),
            ))
            .expect("valid response");
    }
    Response::builder()
        .status(StatusCode::UNAUTHORIZED)
        .header(CONTENT_TYPE, "application/json")
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
        .header(CONTENT_TYPE, "application/json")
        .body(Body::from(
            serde_json::to_vec(&aauth::protocol::AAuthProtocolError::with_description(
                aauth::protocol::AAuthErrorCode::InvalidRequest,
                message.into(),
            ))
            .unwrap_or_default(),
        ))
        .expect("valid response")
}
