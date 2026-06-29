use std::future::Future;
use std::pin::Pin;
use std::sync::Arc;
use std::task::{Context, Poll};

use axum::body::Body;
use axum::http::{Request, Response, StatusCode};
use tower::{Layer, Service};

use crate::headers::{AAuthRequirementParams, build_aauth_requirement};
use crate::jwt::VerifiedToken;
use crate::metadata::MetadataFetcher;
use crate::server::deferred::{
    DeferRequirement, PendingContext, PendingKind, PendingRecord, PendingSnapshot, PendingStore,
    ResourcePendingContext, build_accepted, generate_pending_id, pending_location,
};
use crate::server::policy::{
    ResourceAccessContext, ResourceConsentDecision, ResourceConsentPolicy,
};
use crate::server::resource::audience::resolve_resource_token_audience;
use crate::server::resource::keys::ResourceTokenSigner;
use crate::server::resource::opaque::OpaqueAccessStore;
use crate::server::resource::policy::ResourceAccessMode;
use crate::server::resource::{
    ResourceTokenOptions, VerifyTokenOptions, create_resource_token, verify_token,
};
use crate::signature::verify_request_signature;
use crate::types::RequirementLevel;

#[derive(Clone)]
pub struct ResourceAuthLayer<P, S, O>
where
    P: ResourceConsentPolicy,
    S: PendingStore,
    O: OpaqueAccessStore + Clone,
{
    pub fetcher: Arc<dyn MetadataFetcher>,
    pub resource_url: String,
    pub mode: ResourceAccessMode<P, S, O>,
    pub resource_token_signer: Arc<dyn ResourceTokenSigner>,
}

impl<P, S, O> ResourceAuthLayer<P, S, O>
where
    P: ResourceConsentPolicy,
    S: PendingStore,
    O: OpaqueAccessStore + Clone,
{
    pub fn new(
        fetcher: Arc<dyn MetadataFetcher>,
        resource_url: impl Into<String>,
        mode: ResourceAccessMode<P, S, O>,
        resource_token_signer: Arc<dyn ResourceTokenSigner>,
    ) -> Self {
        Self {
            fetcher,
            resource_url: resource_url.into(),
            mode,
            resource_token_signer,
        }
    }
}

impl<S, P, St, O> Layer<S> for ResourceAuthLayer<P, St, O>
where
    P: ResourceConsentPolicy,
    St: PendingStore,
    O: OpaqueAccessStore + Clone,
{
    type Service = ResourceAuthService<S, P, St, O>;

    fn layer(&self, inner: S) -> Self::Service {
        ResourceAuthService {
            inner,
            fetcher: Arc::clone(&self.fetcher),
            resource_url: self.resource_url.clone(),
            mode: self.mode.clone(),
            resource_token_signer: Arc::clone(&self.resource_token_signer),
        }
    }
}

#[derive(Clone)]
pub struct ResourceAuthService<S, P, St, O>
where
    P: ResourceConsentPolicy,
    St: PendingStore,
    O: OpaqueAccessStore + Clone,
{
    inner: S,
    fetcher: Arc<dyn MetadataFetcher>,
    resource_url: String,
    mode: ResourceAccessMode<P, St, O>,
    resource_token_signer: Arc<dyn ResourceTokenSigner>,
}

impl<S, B, P, St, O> Service<Request<B>> for ResourceAuthService<S, P, St, O>
where
    S: Service<Request<B>, Response = Response<Body>> + Clone + Send + 'static,
    S::Future: Send + 'static,
    S::Error: std::fmt::Display + Send + 'static,
    B: Send + 'static,
    P: ResourceConsentPolicy + Clone + Send + Sync + 'static,
    St: PendingStore + Clone + Send + Sync + 'static,
    O: OpaqueAccessStore + Clone + Send + Sync + 'static,
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
        let mut inner = self.inner.clone();

        Box::pin(async move {
            let (method, authority, path) = request_signature_parts(&req);

            let verified_sig =
                match verify_request_signature(&method, &authority, &path, req.headers()) {
                    Ok(v) => v,
                    Err(e) => return Ok(unauthorized(e.to_string())),
                };

            if let ResourceAccessMode::ResourceManaged { opaque, .. } = &mode {
                if let Some(opaque_token) = extract_aauth_access(req.headers()) {
                    let agent_iss = agent_iss_from_jwt(&verified_sig.jwt);
                    if opaque.validate(&opaque_token, &agent_iss) {
                        if let Ok(VerifiedToken::Agent(agent)) =
                            VerifiedToken::decode_unverified(&verified_sig.jwt)
                        {
                            req.extensions_mut().insert(VerifiedToken::Agent(agent));
                            return inner.call(req).await;
                        }
                    }
                    return Ok(unauthorized("invalid opaque access token".into()));
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
                Err(e) => return Ok(unauthorized(e.to_string())),
            };

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
                        Err(e) => return Ok(unauthorized(e.to_string())),
                    };

                    let resource_token = match create_resource_token(
                        ResourceTokenOptions {
                            resource: resource_url,
                            audience,
                            agent: agent.iss.clone(),
                            agent_jkt: verified_sig.thumbprint,
                            scope: None,
                            mission: None,
                            lifetime: None,
                        },
                        resource_token_signer.as_ref(),
                    )
                    .await
                    {
                        Ok(token) => token,
                        Err(e) => return Ok(unauthorized(e)),
                    };

                    let header = match build_aauth_requirement(
                        RequirementLevel::AuthToken,
                        Some(&AAuthRequirementParams {
                            resource_token: Some(&resource_token),
                            ..Default::default()
                        }),
                    ) {
                        Ok(h) => h,
                        Err(e) => return Ok(unauthorized(e.to_string())),
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
                (
                    ResourceAccessMode::ResourceManaged {
                        policy,
                        pending,
                        opaque,
                        interaction_url,
                        pending_base_url,
                        pending_path,
                        pending_ttl_secs,
                    },
                    VerifiedToken::Agent(agent),
                ) => {
                    let ctx = ResourceAccessContext {
                        resource_url: resource_url.clone(),
                        agent_claims: agent.clone(),
                        scope: None,
                    };

                    match policy.evaluate(&ctx).await {
                        Ok(ResourceConsentDecision::GrantOpaque) => {
                            let token = opaque.issue(&agent.iss);
                            let mut response = Response::builder().status(StatusCode::OK);
                            response = response.header("AAuth-Access", token.as_str());
                            Ok(response.body(Body::empty()).expect("valid response"))
                        }
                        Ok(ResourceConsentDecision::Deny(err)) => Ok(Response::builder()
                            .status(StatusCode::FORBIDDEN)
                            .body(Body::from(err.error))
                            .expect("valid response")),
                        Ok(ResourceConsentDecision::Defer(mut requirement)) => {
                            if let DeferRequirement::Interaction { url, code } = &mut requirement {
                                if url.is_empty() {
                                    *url = interaction_url.clone();
                                }
                                if code.is_empty() {
                                    *code = crate::interaction_code::generate_code();
                                }
                            }
                            let id = generate_pending_id();
                            let location = pending_location(pending_base_url, pending_path, &id);
                            let record = PendingRecord::new(
                                id,
                                PendingKind::ResourceAccess,
                                PendingContext::Resource(ResourcePendingContext {
                                    resource_url: resource_url.clone(),
                                    agent_claims: agent.clone(),
                                    scope: None,
                                }),
                                PendingSnapshot::waiting(requirement.clone()),
                                *pending_ttl_secs,
                            );
                            if pending.create(record).await.is_err() {
                                return Ok(unauthorized("pending store error".into()));
                            }
                            match build_accepted(&location, &requirement) {
                                Ok(accepted) => {
                                    let mut response = Response::builder().status(accepted.status);
                                    for (k, v) in accepted.headers.iter() {
                                        response = response.header(k, v);
                                    }
                                    Ok(response.body(Body::empty()).expect("valid response"))
                                }
                                Err(e) => Ok(unauthorized(e.to_string())),
                            }
                        }
                        Err(e) => Ok(unauthorized(e.to_string())),
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

fn agent_iss_from_jwt(jwt: &str) -> String {
    VerifiedToken::decode_unverified(jwt)
        .map(|t| t.iss().to_string())
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

fn unauthorized(message: String) -> Response<Body> {
    Response::builder()
        .status(StatusCode::UNAUTHORIZED)
        .body(Body::from(message))
        .expect("valid response")
}
