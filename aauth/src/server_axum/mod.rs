mod extract;
mod respond;

pub use extract::PendingResumeInput;
#[cfg(feature = "resource-axum")]
pub use respond::resource_poll_outcome_from_snapshot;
pub use respond::{InternalServiceError, poll_outcome_from_snapshot, polling_status};

#[cfg(feature = "access-server-axum")]
pub use crate::access_server::outcome::{AuthTokenFlowOutcome, AuthTokenPollOutcome};
#[cfg(feature = "person-server-axum")]
pub use crate::person_server::outcome::PersonTokenFlowOutcome;
#[cfg(feature = "resource-axum")]
pub use crate::resource::{ResourceConsentFlowOutcome, ResourcePollOutcome};

#[cfg(feature = "access-server-axum")]
pub use crate::access_server::axum::{
    AccessServerConfig, AccessServerState, access_jwks_handler, access_metadata_handler,
    access_pending_poll_handler, access_pending_post_handler, access_token_exchange_handler,
};
#[cfg(feature = "person-server-axum")]
pub use crate::person_server::axum::{
    PersonServerConfig, PersonServerState, interaction_callback_handler,
    interaction_start_handler, pending_clarification_post_handler, pending_poll_handler,
    pending_post_handler, person_jwks_handler, person_metadata_handler,
    token_exchange_deferred_handler, token_exchange_handler,
};
#[cfg(feature = "resource-axum")]
pub use crate::resource::ResourceAccessMode;
#[cfg(feature = "resource-axum")]
pub use crate::resource::axum::{
    ResourceAuthLayer, ResourceServerState, VerifiedAAuthToken, resource_pending_poll_handler,
};
