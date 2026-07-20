//! Rust implementation of the [AAuth authorization protocol](https://github.com/dickhardt/AAuth).
//!
//! # Features
//!
//! Protocol-wide modules (`error`, `protocol`, `jwt`, `signature`, …) are always available.
//! Enable role-specific features to compile only what you need:
//!
//! - `agent` / `agent-reqwest` — agent runtime and reqwest middleware
//! - `person-server` — Person Server service
//! - `access-server` — Access Server service
//! - `resource` — Resource Server consent service
//! - `resource-verify` — resource token verification only (used by `person-server` and `agent-reqwest-verify`)
//! - `full` — all roles and agent integrations (matches `default`)
//!
//! For axum HTTP adapters (handlers, `ResourceAuthLayer`), use the companion
//! crate `aauth-axum`.
//!
//! Role services, policy traits, and deferred store types live under their modules
//! (`person_server`, `access_server`, `resource`, `policy`, `deferred`). Spec wire
//! types that have no runtime yet (missions, permissions, authorization endpoint, …)
//! live under [`protocol`] only — they are not re-exported at the crate root.
//!
//! # Protocol roles
//!
//! - **Agent** — [`agent`]
//! - **Resource server** — [`resource`]
//! - **Person server** — [`person_server`]
//! - **Access server** — [`access_server`]

pub mod error;
pub mod interaction_code;
pub mod jwt;
pub mod keys;
pub mod metadata;
pub mod protocol;
pub mod signature;

#[cfg(feature = "agent")]
pub mod agent;

#[cfg(feature = "deferred")]
pub mod deferred;
#[cfg(feature = "policy")]
pub mod policy;

#[cfg(feature = "resource-verify")]
pub mod resource_verify;

#[cfg(feature = "access-server")]
pub mod access_server;
#[cfg(feature = "person-server")]
pub mod person_server;
#[cfg(feature = "resource")]
pub mod resource;

#[cfg(feature = "agent")]
pub use agent::keys::{
    AgentJwtMinter, KeyMaterialProvider, StaticKeyMaterialProvider, TestAgentJwtMinter,
    create_key_provider, mint_agent_jwt,
};
#[cfg(feature = "agent")]
pub use agent::resolve::{
    agent_jwt_from_signature_key, person_server_from_agent_jwt, resolve_person_server_url,
};
pub use error::{AAuthError, Result, TokenError};
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

// Common protocol prelude used across roles (not the full governance surface).
pub use protocol::{
    AAuthChallenge, AAuthErrorCode, AAuthProtocolError, AccessServerMetadata,
    AccessTokenExchangeRequest, AgentOkResponse, AgentProviderMetadata, AuthOkResponse, Capability,
    ClaimsChallenge, ClaimsSubmission, ClarificationChallenge, ClarificationResponse, JwksDocument,
    JwtTyp, KeyMaterial, Mission, ParseStrError, PendingBody, PendingPostBody, PendingStatus,
    PendingStatusBody, PersonServerMetadata, RequirementLevel, SignatureKey, SignatureKeyHwk,
    SignatureKeyJktJwt, SignatureKeyJwt, TokenExchangeRequest, TokenResponseBody,
    UpdatedTokenRequest, build_aauth_requirement, build_capabilities_header, build_mission_header,
    parse_aauth_requirement, parse_capabilities_header, parse_mission_header,
};

#[cfg(feature = "deferred")]
pub use deferred::{
    AccessPendingContext, AccessPendingRecord, DEFAULT_PENDING_TTL_SECS, DeferCreated,
    DeferRequirement, DeferWaiting, FederationPendingState, InMemoryAccessPendingStore,
    InMemoryPendingStore, InMemoryPersonPendingStore, InMemoryResourcePendingStore,
    PaymentRequiredDefer, PendingInput, PendingOutcome, PendingRecord, PendingSnapshot,
    PendingStorable, PendingStore, PersonPendingContext, PersonPendingRecord,
    ResourcePendingContext, ResourcePendingRecord, generate_pending_id, parse_pending_post_body,
    pending_location,
};
#[cfg(feature = "deferred")]
pub use deferred::{AuthTokenFlowOutcome, AuthTokenPollOutcome, poll_outcome_from_snapshot};
#[cfg(feature = "deferred-http")]
pub use deferred::{
    OutboundSignatureProvider, ParsedDeferred, ServerPollOptions, ServerPollOutcome,
    parse_auth_token_response, parse_deferred_response, poll_pending_http, post_pending_input,
    resolve_deferred_location,
};

#[cfg(all(feature = "policy", feature = "access-server"))]
pub use policy::{AccessTokenContext, AccessTokenDecision, AccessTokenPolicy};
#[cfg(feature = "policy")]
pub use policy::{AuthGrant, PolicyError};
#[cfg(all(feature = "policy", feature = "person-server"))]
pub use policy::{PersonTokenContext, PersonTokenDecision, PersonTokenPolicy};
#[cfg(all(feature = "policy", feature = "resource"))]
pub use policy::{ResourceAccessContext, ResourceConsentDecision, ResourceConsentPolicy};

#[cfg(feature = "resource-verify")]
pub use resource_verify::{
    VerifyResourceTokenOptions, VerifyTokenOptions, resolve_resource_token_audience,
    verify_auth_token_binding, verify_client_auth_token, verify_resource_challenge,
    verify_resource_token, verify_token,
};

#[cfg(feature = "person-server")]
pub use person_server::{
    FederationOutcome, PersonAuthJwtMinter, PersonServerConfig, PersonServerOutboundSigner,
    PersonTokenFlowOutcome, PersonTokenService, PersonTokenServiceError, PolicyPersonTokenService,
    TestPersonAuthJwtMinter, federate_to_access_server, mint_person_auth_jwt,
    verify_federated_auth_token, verify_person_token_request,
};

#[cfg(feature = "access-server")]
pub use access_server::{
    AccessAuthJwtMinter, AccessServerConfig, AccessTokenService, AccessTokenServiceError,
    PolicyAccessTokenService, TestAccessAuthJwtMinter, build_access_context, mint_access_auth_jwt,
};

#[cfg(feature = "resource")]
pub use resource::{
    Ed25519ResourceTokenSigner, InMemoryOpaqueAccessStore, OpaqueAccessStore,
    PolicyResourceAccessService, ResourceAccessConfig, ResourceAccessMode,
    ResourceAccessPolicyService, ResourceAccessService, ResourceAccessServiceError,
    ResourceConsentFlowOutcome, ResourceInteractionContext, ResourceInteractionProvider,
    ResourcePollOutcome, ResourceTokenOptions, ResourceTokenSigner, create_resource_token,
};
