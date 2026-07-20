mod deferred;
mod metadata;
mod middleware;
pub(crate) mod send;
pub mod signed;
mod token_exchange;

pub use super::auth::{
    AgentAuth, AgentAuthAttempt, AgentAuthStep, AgentOptions, AgentOptionsBuilder,
    ClarificationCallback, InteractionCallback,
};
pub use deferred::{
    AgentDeferredOptions, AgentDeferredOptionsBuilder, DeferredResult, poll_deferred,
};
pub use metadata::CachedMetadataFetcher;
pub use middleware::{AgentMiddleware, ClientBuilder, ClientWithMiddleware};
pub use signed::{
    SigningOptions, apply_capability_mission, apply_opaque_token, sign_request,
    sign_request_with_auth_token,
};
pub use token_exchange::{
    TokenExchangeError, TokenExchangeOptions, TokenExchangeOptionsBuilder, TokenExchangeResult,
    exchange_token,
};

pub use reqwest;
pub use reqwest_middleware;
