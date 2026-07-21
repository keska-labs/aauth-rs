//! Reqwest transport adapter for the AAuth agent client.
//!
//! Pair [`AgentMiddleware`] with [`aauth::agent::auth::AgentOptions`] (re-exported here)
//! to drive signed requests, token exchange, and deferred polling over HTTP.
//!
//! Enable the `verify` feature (on by default) to verify resource challenges and
//! auth tokens when a [`aauth::metadata::MetadataFetcher`] is configured on
//! [`AgentOptions`].

mod deferred;
mod error;
mod metadata;
mod middleware;
mod send;
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
