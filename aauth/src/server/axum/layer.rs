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
use crate::server::keys::ResourceTokenSigner;
use crate::server::{ResourceTokenOptions, VerifyTokenOptions, create_resource_token, verify_token};
use crate::signature::verify_request_signature;
use crate::types::RequirementLevel;

#[derive(Clone)]
pub struct AAuthLayer<F: MetadataFetcher> {
    pub fetcher: Arc<F>,
    pub resource_url: String,
    pub auth_server_url: String,
    pub require_auth_token: bool,
    pub resource_token_signer: Arc<dyn ResourceTokenSigner>,
}

impl<F: MetadataFetcher> AAuthLayer<F> {
    pub fn new(
        fetcher: Arc<F>,
        resource_url: impl Into<String>,
        auth_server_url: impl Into<String>,
        require_auth_token: bool,
        resource_token_signer: Arc<dyn ResourceTokenSigner>,
    ) -> Self {
        Self {
            fetcher,
            resource_url: resource_url.into(),
            auth_server_url: auth_server_url.into(),
            require_auth_token,
            resource_token_signer,
        }
    }
}

impl<S, F: MetadataFetcher + Clone + 'static> Layer<S> for AAuthLayer<F> {
    type Service = AAuthService<S, F>;

    fn layer(&self, inner: S) -> Self::Service {
        AAuthService {
            inner,
            fetcher: Arc::clone(&self.fetcher),
            resource_url: self.resource_url.clone(),
            auth_server_url: self.auth_server_url.clone(),
            require_auth_token: self.require_auth_token,
            resource_token_signer: Arc::clone(&self.resource_token_signer),
        }
    }
}

#[derive(Clone)]
pub struct AAuthService<S, F: MetadataFetcher> {
    inner: S,
    fetcher: Arc<F>,
    resource_url: String,
    auth_server_url: String,
    require_auth_token: bool,
    resource_token_signer: Arc<dyn ResourceTokenSigner>,
}

impl<S, F, B> Service<Request<B>> for AAuthService<S, F>
where
    S: Service<Request<B>, Response = Response<Body>> + Clone + Send + 'static,
    S::Future: Send + 'static,
    S::Error: std::fmt::Display + Send + 'static,
    F: MetadataFetcher + Send + Sync + 'static,
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
        let auth_server_url = self.auth_server_url.clone();
        let require_auth_token = self.require_auth_token;
        let resource_token_signer = Arc::clone(&self.resource_token_signer);
        let mut inner = self.inner.clone();

        Box::pin(async move {
            let (method, authority, path) = request_signature_parts(&req);

            let verified_sig = match verify_request_signature(
                &method,
                &authority,
                &path,
                req.headers(),
            ) {
                Ok(v) => v,
                Err(e) => return Ok(unauthorized(e.to_string())),
            };

            let verified = match verify_token(VerifyTokenOptions {
                jwt: verified_sig.jwt,
                http_signature_thumbprint: verified_sig.thumbprint.clone(),
                fetcher,
            })
            .await
            {
                Ok(v) => v,
                Err(e) => return Ok(unauthorized(e.to_string())),
            };

            match verified {
                VerifiedToken::Auth(_) => {
                    req.extensions_mut().insert(verified);
                    inner.call(req).await
                }
                VerifiedToken::Agent(agent) if require_auth_token => {
                    let resource_token = match create_resource_token(
                        ResourceTokenOptions {
                            resource: resource_url,
                            auth_server: auth_server_url,
                            agent: agent.iss,
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
                VerifiedToken::Agent(_) => {
                    req.extensions_mut().insert(verified);
                    inner.call(req).await
                }
            }
        })
    }
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
