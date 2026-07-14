pub mod keys;

#[cfg(feature = "resource-axum")]
pub mod axum;

mod interaction;
mod mode;
mod opaque;
mod outcome;
mod service;
mod token;

pub use crate::resource_verify::{
    VerifyResourceTokenOptions, VerifyTokenOptions, resolve_resource_token_audience,
    verify_auth_token_binding, verify_client_auth_token, verify_resource_challenge,
    verify_resource_token, verify_token,
};
pub use interaction::{ResourceInteractionContext, ResourceInteractionProvider};
pub use keys::{Ed25519ResourceTokenSigner, ResourceTokenSigner};
pub use mode::{ResourceAccessMode, ResourceAccessPolicy, ResourceAccessPolicyService};
pub use opaque::{InMemoryOpaqueAccessStore, OpaqueAccessStore};
pub use outcome::{ResourceConsentFlowOutcome, ResourcePollOutcome};
pub use service::{
    PolicyResourceAccessService, ResourceAccessConfig, ResourceAccessService,
    ResourceAccessServiceError,
};
pub use token::{ResourceTokenOptions, create_resource_token};
