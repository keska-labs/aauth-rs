#![doc = include_str!("../README.md")]

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
pub use error::{PersonOrchestrationError, PolicyError};
pub use store::{
    AccessPendingContext, AccessPendingRecord, FederationPendingState, InMemoryAccessPendingStore,
    InMemoryPendingStore, InMemoryPersonPendingStore, InMemoryResourcePendingStore, PendingRecord,
    PendingStorable, PendingStore, PersonPendingContext, PersonPendingRecord,
    ResourcePendingContext, ResourcePendingRecord, poll_auth_pending,
};

#[cfg(feature = "access-server")]
pub use access::{
    AccessTokenPolicy, AccessTokenServiceError, DynAccessTokenPolicy, LocalAccessTokenPolicy,
    PolicyAccessTokenService,
};
#[cfg(feature = "person-server")]
pub use person::{
    DynPersonTokenPolicy, LocalPersonTokenPolicy, PersonTokenPolicy, PersonTokenServiceError,
    PolicyPersonTokenService,
};
#[cfg(feature = "resource")]
pub use resource::{
    DynResourceConsentPolicy, InMemoryOpaqueAccessStore, LocalResourceConsentPolicy,
    OpaqueAccessStore, PolicyResourceAccessService, ResourceAccessServiceError,
    ResourceConsentPolicy,
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
