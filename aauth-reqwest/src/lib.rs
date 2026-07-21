#![doc = include_str!("../README.md")]

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
