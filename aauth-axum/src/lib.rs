#![doc = include_str!("../README.md")]

// Run workspace README snippets as doctests (`cargo test -p aauth-axum --doc --features full`).
#[cfg(doctest)]
#[doc = include_str!("../../README.md")]
mod readme_workspace {}

mod extract;
mod respond;

#[cfg(feature = "access-server")]
pub mod access;
#[cfg(feature = "person-server")]
pub mod person;
#[cfg(feature = "resource")]
pub mod resource;

pub use extract::PendingResumeInput;
pub use respond::{AauthResponse, InternalServiceError, polling_status};

#[cfg(feature = "access-server")]
pub use access::{
    AccessServerState, access_jwks_handler, access_metadata_handler, access_pending_poll_handler,
    access_pending_post_handler, access_router, access_token_exchange_handler,
};
#[cfg(feature = "person-server")]
pub use person::{
    PersonServerState, interaction_callback_handler, interaction_start_handler,
    pending_clarification_post_handler, pending_poll_handler, pending_post_handler,
    person_jwks_handler, person_metadata_handler, person_router, token_exchange_deferred_handler,
    token_exchange_handler,
};
#[cfg(feature = "resource")]
pub use resource::{
    ResourceAuthLayer, ResourceServerState, VerifiedAAuthToken, resource_authorize_handler,
    resource_pending_poll_handler, resource_router,
};
