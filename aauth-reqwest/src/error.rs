use aauth::{AAuthError, AgentAuthError, DeferredError, JwtError, MetadataError, SignatureError};

use crate::token_exchange::TokenExchangeError;

/// Errors from the reqwest agent transport (`AgentMiddleware`, exchange, poll, signing).
#[derive(Debug, thiserror::Error)]
pub enum AgentError {
    #[error(transparent)]
    Auth(#[from] AgentAuthError),

    #[error(transparent)]
    Exchange(#[from] TokenExchangeError),

    #[error(transparent)]
    Deferred(#[from] DeferredError),

    #[error(transparent)]
    Signature(#[from] SignatureError),

    #[error(transparent)]
    Jwt(#[from] JwtError),

    #[error(transparent)]
    Metadata(#[from] MetadataError),

    #[error(transparent)]
    Aauth(#[from] AAuthError),

    #[error("middleware error")]
    Middleware(Box<dyn std::error::Error + Send + Sync>),

    #[error("request body is not cloneable")]
    BodyNotCloneable,
}

impl From<httpsig_key::Error> for AgentError {
    fn from(err: httpsig_key::Error) -> Self {
        Self::Signature(err.into())
    }
}

pub type Result<T> = std::result::Result<T, AgentError>;

/// Map a `reqwest_middleware` failure back to [`AgentError`], preferring a downcast when the
/// middleware layer wrapped an [`AgentError`] in `anyhow`.
pub(crate) fn from_middleware_error(err: reqwest_middleware::Error) -> AgentError {
    match err {
        reqwest_middleware::Error::Middleware(e) => AgentError::Middleware(e),
        reqwest_middleware::Error::Reqwest(e) => MetadataError::Request {
            url: "request".into(),
            source: Box::new(e),
        }
        .into(),
    }
}
