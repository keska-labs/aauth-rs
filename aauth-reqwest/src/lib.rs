//! Reqwest transport adapter for the AAuth agent client.
//!
//! Pair [`AgentMiddleware`] with [`aauth::agent::auth::AgentOptions`] (re-exported here)
//! to drive signed requests, token exchange, and deferred polling over HTTP.
//!
//! Challenge verification always runs before token exchange. Auth-token claim binding
//! always runs after exchange. JWT signature verification of returned auth tokens is
//! controlled by [`AgentOptions::verify_auth_signature`] (default `true`, spec SHOULD).
//! Provide a [`aauth::metadata::MetadataFetcher`] (for example [`CachedMetadataFetcher`])
//! so JWKS discovery succeeds for challenges and optional auth signatures.

mod deferred;
mod error;
mod metadata;
mod middleware;
pub mod signed;
mod token_exchange;

pub use aauth::agent::auth::{
    AgentAuth, AgentAuthAttempt, AgentAuthStep, AgentOptions, AgentOptionsBuilder,
    ClarificationCallback, InteractionCallback,
};
pub use deferred::{
    AgentDeferredOptions, AgentDeferredOptionsBuilder, DeferredResult, poll_deferred,
};
pub use error::{AgentError, Result};
pub use metadata::CachedMetadataFetcher;
pub use middleware::{AgentMiddleware, ClientBuilder, ClientWithMiddleware};
pub use signed::{RequestSigningExt, SigningOptions};
pub use token_exchange::{
    TokenExchangeError, TokenExchangeOptions, TokenExchangeOptionsBuilder, TokenExchangeResult,
    exchange_token,
};

pub use reqwest;
pub use reqwest_middleware;
