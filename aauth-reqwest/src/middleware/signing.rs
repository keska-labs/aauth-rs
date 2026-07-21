use std::sync::Arc;

use aauth::DynKeyMaterialProvider;
use aauth::KeyMaterialProvider;
use aauth::agent::auth::AgentAuthAttempt;
use http::Extensions;
use reqwest::{Request, Response};
use reqwest_middleware::{Middleware, Next, Result as MiddlewareResult};

use crate::error::AgentError;
use crate::signed::{RequestSigningExt, SigningOptions, apply_opaque_token};

#[derive(Clone)]
pub(crate) struct AgentAuthAttemptKey(pub AgentAuthAttempt);

pub(crate) struct SigningMiddleware {
    provider: Arc<DynKeyMaterialProvider<'static>>,
    options: SigningOptions,
}

impl SigningMiddleware {
    pub(crate) fn new(
        provider: Arc<DynKeyMaterialProvider<'static>>,
        options: SigningOptions,
    ) -> Self {
        Self { provider, options }
    }

    pub(crate) async fn sign_and_run(
        &self,
        mut req: Request,
        attempt: AgentAuthAttempt,
        extensions: &mut Extensions,
        next: Next<'_>,
    ) -> MiddlewareResult<Response> {
        let material = self.provider.as_ref().key_material().await.map_err(|e| {
            reqwest_middleware::Error::Middleware(anyhow::Error::from(AgentError::from(e)))
        })?;

        self.options.apply_to(&mut req);

        match &attempt {
            AgentAuthAttempt::AuthToken(token) => {
                req.sign_with_auth_token(&material, token)
                    .map_err(|e| reqwest_middleware::Error::Middleware(anyhow::Error::from(e)))?;
            }
            AgentAuthAttempt::OpaqueToken(token) => {
                apply_opaque_token(&mut req, token);
                req.sign(&material)
                    .map_err(|e| reqwest_middleware::Error::Middleware(anyhow::Error::from(e)))?;
            }
            AgentAuthAttempt::AgentSigned => {
                req.sign(&material)
                    .map_err(|e| reqwest_middleware::Error::Middleware(anyhow::Error::from(e)))?;
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
