use std::sync::Arc;

use anyhow::anyhow;
use http::Extensions;
use reqwest::{Request, Response};
use reqwest_middleware::{Middleware, Next, Result as MiddlewareResult};

use crate::client::injector::AuthAttempt;
use crate::client::keys::KeyMaterialProvider;
use crate::client::reqwest::signed::{
    SigningOptions, apply_capability_mission, apply_opaque_token, sign_request,
    sign_request_with_auth_token,
};
use crate::error::{AAuthError, Result};

#[derive(Clone)]
pub(crate) struct AuthAttemptKey(pub AuthAttempt);

pub(crate) struct SigningMiddleware {
    provider: Arc<dyn KeyMaterialProvider>,
    options: SigningOptions,
}

impl SigningMiddleware {
    pub(crate) fn new(provider: Arc<dyn KeyMaterialProvider>, options: SigningOptions) -> Self {
        Self { provider, options }
    }

    pub(crate) async fn sign_and_run(
        &self,
        mut req: Request,
        attempt: AuthAttempt,
        extensions: &mut Extensions,
        next: Next<'_>,
    ) -> MiddlewareResult<Response> {
        let material = self
            .provider
            .key_material()
            .await
            .map_err(|e| reqwest_middleware::Error::Middleware(anyhow!(e.to_string())))?;

        apply_capability_mission(&mut req, &self.options);

        match &attempt {
            AuthAttempt::AuthToken(token) => {
                sign_request_with_auth_token(&mut req, &material, token)
                    .map_err(|e| reqwest_middleware::Error::Middleware(anyhow!(e.to_string())))?;
            }
            AuthAttempt::OpaqueToken(token) => {
                apply_opaque_token(&mut req, token);
                sign_request(&mut req, &material)
                    .map_err(|e| reqwest_middleware::Error::Middleware(anyhow!(e.to_string())))?;
            }
            AuthAttempt::AgentSigned => {
                sign_request(&mut req, &material)
                    .map_err(|e| reqwest_middleware::Error::Middleware(anyhow!(e.to_string())))?;
            }
        }

        extensions.insert(AuthAttemptKey(attempt));
        next.run(req, extensions).await
    }
}

#[async_trait::async_trait]
impl Middleware for SigningMiddleware {
    async fn handle(
        &self,
        req: Request,
        extensions: &mut Extensions,
        next: Next<'_>,
    ) -> MiddlewareResult<Response> {
        let attempt = extensions
            .get::<AuthAttemptKey>()
            .cloned()
            .unwrap_or(AuthAttemptKey(AuthAttempt::AgentSigned))
            .0;
        self.sign_and_run(req, attempt, extensions, next).await
    }
}

pub(crate) async fn sign_and_run(
    signing: &SigningMiddleware,
    req: Request,
    attempt: AuthAttempt,
    extensions: &mut Extensions,
    next: Next<'_>,
) -> Result<Response> {
    signing
        .sign_and_run(req, attempt, extensions, next)
        .await
        .map_err(|e| AAuthError::Message(e.to_string()))
}
