#[cfg(feature = "access-server")]
mod access;
mod decision;
mod error;
#[cfg(feature = "person-server")]
mod person;
#[cfg(feature = "resource")]
mod resource;
#[cfg(any(
    feature = "person-server",
    feature = "access-server",
    feature = "resource"
))]
mod test;

#[cfg(feature = "access-server")]
pub use access::{AccessTokenContext, AccessTokenPolicy};
pub use decision::{AccessTokenDecision, AuthGrant, PersonTokenDecision, ResourceConsentDecision};
pub use error::PolicyError;
#[cfg(feature = "person-server")]
pub use person::{PersonTokenContext, PersonTokenPolicy};
#[cfg(feature = "resource")]
pub use resource::{ResourceAccessContext, ResourceConsentPolicy};
#[cfg(feature = "access-server")]
pub use test::{
    AlwaysGrantAccessPolicy, ClarificationThenGrantAccessPolicy, DeferApprovalAccessPolicy,
    DeferClaimsAccessPolicy, DeferInteractionAccessPolicy,
};
#[cfg(feature = "person-server")]
pub use test::{
    AlwaysGrantPersonPolicy, ClarificationThenGrantPersonPolicy, DeferInteractionPersonPolicy,
};
#[cfg(feature = "resource")]
pub use test::{AlwaysGrantResourcePolicy, DeferInteractionResourcePolicy};
