pub mod keys;

#[cfg(feature = "server-axum")]
pub mod axum;

mod audience;
mod opaque;
mod outcome;
mod policy;
mod service;
mod token;
mod verify;

pub use audience::resolve_resource_token_audience;
pub use keys::{Ed25519ResourceTokenSigner, ResourceTokenSigner};
pub use opaque::{InMemoryOpaqueAccessStore, OpaqueAccessStore};
pub use outcome::{ResourceConsentFlowOutcome, ResourcePollOutcome};
pub use policy::{ResourceAccessMode, ResourceAccessPolicy, ResourceAccessPolicyService};
pub use service::{
    PolicyResourceAccessService, ResourceAccessConfig, ResourceAccessService,
    ResourceAccessServiceError,
};
pub use token::{ResourceTokenOptions, create_resource_token};
pub use verify::{
    VerifyResourceTokenOptions, VerifyTokenOptions, verify_auth_token_binding,
    verify_client_auth_token, verify_resource_challenge, verify_resource_token, verify_token,
};
