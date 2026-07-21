//! High-level policy helpers for AAuth.
//!
//! This crate is intentionally more opinionated than [`aauth`]: it provides
//! stateless policy traits, a [`PendingStore`] persistence model with fixed
//! pending-record schemas, in-memory stores, and policy-backed services that
//! implement the role service traits from `aauth`.
//!
//! Production integrators may implement `aauth` role service traits directly
//! with their own persistence and never depend on this crate.

pub mod decision;
pub mod error;
pub mod store;

#[cfg(feature = "access-server")]
pub mod access;
#[cfg(feature = "person-server")]
pub mod person;
#[cfg(feature = "resource")]
pub mod resource;

#[cfg(any(
    feature = "person-server",
    feature = "access-server",
    feature = "resource"
))]
mod policies;

pub use decision::{AccessTokenDecision, AuthGrant, PersonTokenDecision, ResourceConsentDecision};
pub use error::PolicyError;
pub use store::{
    AccessPendingContext, AccessPendingRecord, FederationPendingState, InMemoryAccessPendingStore,
    InMemoryPendingStore, InMemoryPersonPendingStore, InMemoryResourcePendingStore, PendingRecord,
    PendingStorable, PendingStore, PersonPendingContext, PersonPendingRecord,
    ResourcePendingContext, ResourcePendingRecord, poll_auth_pending,
};

#[cfg(feature = "access-server")]
pub use access::{AccessTokenPolicy, AccessTokenServiceError, PolicyAccessTokenService};
#[cfg(feature = "person-server")]
pub use person::{PersonTokenPolicy, PersonTokenServiceError, PolicyPersonTokenService};
#[cfg(feature = "resource")]
pub use resource::{
    InMemoryOpaqueAccessStore, OpaqueAccessStore, PolicyResourceAccessService,
    ResourceAccessServiceError, ResourceConsentPolicy,
};

#[cfg(feature = "access-server")]
pub use policies::{
    AlwaysGrantAccessPolicy, ClarificationThenGrantAccessPolicy, DeferApprovalAccessPolicy,
    DeferClaimsAccessPolicy, DeferInteractionAccessPolicy,
};
#[cfg(feature = "person-server")]
pub use policies::{
    AlwaysGrantPersonPolicy, ClarificationThenGrantPersonPolicy, DeferInteractionPersonPolicy,
};
#[cfg(feature = "resource")]
pub use policies::{AlwaysGrantResourcePolicy, DeferInteractionResourcePolicy};

#[cfg(feature = "resource")]
/// Default resource-managed mode using in-memory policy, pending store, and opaque tokens.
pub type ResourceAccessPolicyService = PolicyResourceAccessService<
    AlwaysGrantResourcePolicy,
    InMemoryResourcePendingStore,
    InMemoryOpaqueAccessStore,
>;
