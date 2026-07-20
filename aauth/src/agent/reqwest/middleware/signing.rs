use std::sync::Arc;

use anyhow::anyhow;
use http::Extensions;
use reqwest::{Request, Response};
use reqwest_middleware::{Middleware, Next, Result as MiddlewareResult};

use crate::agent::auth::AgentAuthAttempt;
use crate::agent::keys::KeyMaterialProvider;
use crate::agent::reqwest::signed::{
    SigningOptions, apply_capability_mission, apply_opaque_token, sign_request,
    sign_request_with_auth_token,
};
use crate::error::{AAuthError, Result};

#[derive(Clone)]
pub(crate) struct AgentAuthAttemptKey(pub AgentAuthAttempt);

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
        attempt: AgentAuthAttempt,
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
            AgentAuthAttempt::AuthToken(token) => {
                sign_request_with_auth_token(&mut req, &material, token)
                    .map_err(|e| reqwest_middleware::Error::Middleware(anyhow!(e.to_string())))?;
            }
            AgentAuthAttempt::OpaqueToken(token) => {
                apply_opaque_token(&mut req, token);
                sign_request(&mut req, &material)
                    .map_err(|e| reqwest_middleware::Error::Middleware(anyhow!(e.to_string())))?;
            }
            AgentAuthAttempt::AgentSigned => {
                sign_request(&mut req, &material)
                    .map_err(|e| reqwest_middleware::Error::Middleware(anyhow!(e.to_string())))?;
            }
        }

        extensions.insert(AgentAuthAttemptKey(attempt));
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
            .get::<AgentAuthAttemptKey>()
            .cloned()
            .unwrap_or(AgentAuthAttemptKey(AgentAuthAttempt::AgentSigned))
            .0;
        self.sign_and_run(req, attempt, extensions, next).await
    }
}

pub(crate) async fn sign_and_run(
    signing: &SigningMiddleware,
    req: Request,
    attempt: AgentAuthAttempt,
    extensions: &mut Extensions,
    next: Next<'_>,
) -> Result<Response> {
    signing
        .sign_and_run(req, attempt, extensions, next)
        .await
        .map_err(|e| AAuthError::Message(e.to_string()))
}
