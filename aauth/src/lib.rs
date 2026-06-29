//! Rust implementation of the [AAuth authorization protocol](https://github.com/dickhardt/AAuth).
//!
//! # Features
//!
//! - `client` — framework-agnostic auth flow and key material (`client::injector`, `client::keys`)
//! - `client-reqwest` — reqwest middleware and token exchange (`client::reqwest`)
//! - `server` — token verification, resource token creation, policy traits, pending store
//! - `server-axum` — axum middleware and route helpers (`server::axum`)
//!
//! # Protocol roles
//!
//! - **Agent** — [`client`]
//! - **Resource server** — [`server::resource`]
//! - **Person server** — [`server::person`]
//! - **Access server** — [`server::access`]

pub mod error;
pub mod headers;
pub mod interaction_code;
pub mod jwt;
pub mod keys;
pub mod metadata;
pub mod signature;
pub mod types;

#[cfg(feature = "client")]
pub mod client;

#[cfg(feature = "server")]
pub mod server;

#[cfg(feature = "client")]
pub use client::keys::{
    AgentJwtMinter, KeyMaterialProvider, StaticKeyMaterialProvider, TestAgentJwtMinter,
    create_key_provider, mint_agent_jwt,
};
#[cfg(feature = "client")]
pub use client::resolve::{
    agent_jwt_from_signature_key, person_server_from_agent_jwt, resolve_person_server_url,
    resource_token_audience_unverified,
};
pub use error::{AAuthError, Result, TokenError};
pub use headers::{
    build_aauth_requirement, build_capabilities_header, build_mission_header,
    parse_aauth_requirement, parse_capabilities_header, parse_mission_header,
};
pub use interaction_code::{canonicalize_code, generate_code};
pub use jwt::{
    ActClaim, AgentClaims, AuthClaims, CnfClaim, OkpJwk, OkpSigningJwk, ResourceClaims,
    ResourceInteractionClaim, VerifiedToken, decode_resource_token_unverified, jwk_set_from_okp,
    jwk_thumbprint,
};
pub use keys::{
    Ed25519KeyPair, OkpSigningKey, TestKeys, create_test_keys, static_agent_metadata_fetcher,
    static_person_metadata_fetcher,
};
pub use metadata::{MetadataFetcher, StaticMetadataFetcher};
#[cfg(all(feature = "server", feature = "server-axum"))]
pub use server::access::{
    AccessAuthJwtMinter, AccessServerMetadata, TestAccessAuthJwtMinter, mint_access_auth_jwt,
};
#[cfg(all(feature = "server", feature = "server-axum"))]
pub use server::deferred::{build_accepted, build_payment_required_stub};
#[cfg(feature = "server")]
pub use server::person::{
    FederationConfig, FederationOutcome, federate_to_access_server, fulfill_token_exchange,
    verify_federated_auth_token,
};
#[cfg(feature = "server")]
pub use server::{
    AccessTokenContext, AccessTokenPolicy, AlwaysGrantAccessPolicy, AlwaysGrantPersonPolicy,
    AlwaysGrantResourcePolicy, AuthGrant, AuthJwtMinter, ClaimsSubmission,
    ClarificationThenGrantAccessPolicy, ClarificationThenGrantPersonPolicy,
    DEFAULT_PENDING_TTL_SECS, DeferApprovalAccessPolicy, DeferClaimsAccessPolicy,
    DeferInteractionAccessPolicy, DeferInteractionPersonPolicy, DeferInteractionResourcePolicy,
    DeferRequirement, Ed25519ResourceTokenSigner, FederationPendingState, FixedSubPersonPolicy,
    InMemoryOpaqueAccessStore, InMemoryPendingStore, OpaqueAccessStore, PendingContext,
    PendingInput, PendingKind, PendingOutcome, PendingRecord, PendingSnapshot, PendingStatus,
    PendingStore, PersonPendingContext, PersonTokenContext, PersonTokenDecision, PersonTokenPolicy,
    PolicyError, ResourceAccessContext, ResourceAccessMode, ResourceAccessPolicy,
    ResourceConsentDecision, ResourceConsentPolicy, ResourceTokenOptions, ResourceTokenSigner,
    TestAuthJwtMinter, TokenPolicyDecision, VerifyResourceTokenOptions, VerifyTokenOptions,
    create_resource_token, generate_pending_id, mint_auth_jwt, pending_location,
    resolve_resource_token_audience, verify_auth_token_binding, verify_client_auth_token,
    verify_resource_challenge, verify_resource_token, verify_token,
};
pub use types::*;
