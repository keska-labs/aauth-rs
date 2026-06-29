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
use crate::server::resource::audience::resolve_resource_token_audience;
use crate::server::resource::keys::ResourceTokenSigner;
use crate::server::resource::policy::ResourceAccessPolicy;
use crate::server::resource::{
    ResourceTokenOptions, VerifyTokenOptions, create_resource_token, verify_token,
};
use crate::signature::verify_request_signature;
use crate::types::RequirementLevel;

#[derive(Clone)]
pub struct AAuthLayer {
    pub fetcher: Arc<dyn MetadataFetcher>,
    pub resource_url: String,
    pub policy: ResourceAccessPolicy,
    pub resource_token_signer: Arc<dyn ResourceTokenSigner>,
}

impl AAuthLayer {
    pub fn new(
        fetcher: Arc<dyn MetadataFetcher>,
        resource_url: impl Into<String>,
        policy: ResourceAccessPolicy,
        resource_token_signer: Arc<dyn ResourceTokenSigner>,
    ) -> Self {
        Self {
            fetcher,
            resource_url: resource_url.into(),
            policy,
            resource_token_signer,
        }
    }
}

impl<S> Layer<S> for AAuthLayer {
    type Service = AAuthService<S>;

    fn layer(&self, inner: S) -> Self::Service {
        AAuthService {
            inner,
            fetcher: Arc::clone(&self.fetcher),
            resource_url: self.resource_url.clone(),
            policy: self.policy.clone(),
            resource_token_signer: Arc::clone(&self.resource_token_signer),
        }
    }
}

#[derive(Clone)]
pub struct AAuthService<S> {
    inner: S,
    fetcher: Arc<dyn MetadataFetcher>,
    resource_url: String,
    policy: ResourceAccessPolicy,
    resource_token_signer: Arc<dyn ResourceTokenSigner>,
}

impl<S, B> Service<Request<B>> for AAuthService<S>
where
    S: Service<Request<B>, Response = Response<Body>> + Clone + Send + 'static,
    S::Future: Send + 'static,
    S::Error: std::fmt::Display + Send + 'static,
    B: Send + 'static,
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
        let policy = self.policy.clone();
        let resource_token_signer = Arc::clone(&self.resource_token_signer);
        let mut inner = self.inner.clone();

        Box::pin(async move {
            let (method, authority, path) = request_signature_parts(&req);

            let verified_sig =
                match verify_request_signature(&method, &authority, &path, req.headers()) {
                    Ok(v) => v,
                    Err(e) => return Ok(unauthorized(e.to_string())),
                };

            if let ResourceAccessPolicy::ResourceManaged { opaque_store, .. } = &policy {
                if let Some(opaque) = extract_aauth_access(req.headers()) {
                    let agent_iss = agent_iss_from_jwt(&verified_sig.jwt);
                    if opaque_store.validate(&opaque, &agent_iss) {
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

            match (&policy, &verified) {
                (ResourceAccessPolicy::IdentityBased, _) => {
                    req.extensions_mut().insert(verified);
                    inner.call(req).await
                }
                (
                    ResourceAccessPolicy::PsAsserted {
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
                (ResourceAccessPolicy::PsAsserted { .. }, _) => {
                    req.extensions_mut().insert(verified);
                    inner.call(req).await
                }
                (
                    ResourceAccessPolicy::ResourceManaged {
                        interaction_manager,
                        opaque_store: _,
                        pending_id_capture,
                    },
                    VerifiedToken::Agent(_agent),
                ) => {
                    let (headers, pending) = interaction_manager.create_pending();
                    if let Some(capture) = pending_id_capture {
                        *capture.lock().unwrap() = Some(pending.id.clone());
                    }

                    let mut response = Response::builder().status(StatusCode::ACCEPTED);
                    for (name, value) in headers {
                        response = response.header(name, value);
                    }
                    Ok(response.body(Body::empty()).expect("valid response"))
                }
                (ResourceAccessPolicy::ResourceManaged { .. }, VerifiedToken::Auth(_)) => {
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
