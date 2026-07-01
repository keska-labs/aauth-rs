//! Rust implementation of the [AAuth authorization protocol](https://github.com/dickhardt/AAuth).
//!
//! # Features
//!
//! Protocol-wide modules (`error`, `protocol`, `jwt`, `signature`, …) are always available.
//! Enable role-specific features to compile only what you need:
//!
//! - `agent` / `agent-reqwest` — agent runtime and reqwest middleware
//! - `person-server` / `person-server-axum` — Person Server service and axum routes
//! - `access-server` / `access-server-axum` — Access Server service and axum routes
//! - `resource` / `resource-axum` — Resource Server layer, consent service, and axum helpers
//! - `resource-verify` — resource token verification only (used by `person-server` and `agent-reqwest-verify`)
//! - `full` — all roles and integrations (matches `default`)
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

#[cfg(any(
    feature = "person-server-axum",
    feature = "access-server-axum",
    feature = "resource-axum"
))]
pub mod server_axum;

#[cfg(feature = "agent")]
pub use agent::keys::{
    AgentJwtMinter, KeyMaterialProvider, StaticKeyMaterialProvider, TestAgentJwtMinter,
    create_key_provider, mint_agent_jwt,
};
#[cfg(feature = "agent")]
pub use agent::resolve::{
    agent_jwt_from_signature_key, person_server_from_agent_jwt, resolve_person_server_url,
    resource_token_audience_unverified,
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
pub use protocol::{
    AAuthChallenge, AAuthErrorCode, AAuthProtocolError, AccessServerMetadata,
    AccessTokenExchangeRequest, AgentOkResponse, AgentProviderMetadata, AuditRequest,
    AuthOkResponse, AuthorizationGrantedResponse, AuthorizationRequest, Capability,
    ClaimsChallenge, ClaimsSubmission, ClarificationChallenge, ClarificationResponse,
    InteractionQuestionResponse, InteractionRequest, InteractionType, JwksDocument, JwtTyp,
    KeyMaterial, Mission, MissionBlob, MissionProposalRequest, MissionStatusError, MissionTool,
    ParseStrError, PendingBody, PendingPostBody, PendingStatus, PendingStatusBody,
    PermissionDecision, PermissionRequest, PermissionResponse, PersonServerMetadata,
    RequirementLevel, ResourceAccessModeWire, ResourceServerMetadata, ResourceTokenResponse,
    RevocationRequest, SignatureKey, SignatureKeyHwk, SignatureKeyJktJwt, SignatureKeyJwt,
    TokenExchangeRequest, TokenResponseBody, UpdatedTokenRequest, build_aauth_requirement,
    build_capabilities_header, build_mission_header, parse_aauth_requirement,
    parse_capabilities_header, parse_mission_header,
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
pub use deferred::{AuthTokenFlowOutcome, AuthTokenPollOutcome};
#[cfg(feature = "deferred-http")]
pub use deferred::{
    OutboundSignatureProvider, ParsedDeferred, ServerPollOptions, ServerPollOutcome,
    parse_auth_token_response, parse_deferred_response, poll_pending_http, post_pending_input,
    resolve_deferred_location,
};

#[cfg(all(feature = "policy", feature = "access-server"))]
pub use policy::{AccessTokenContext, AccessTokenPolicy, TokenPolicyDecision};
#[cfg(all(feature = "policy", feature = "access-server"))]
pub use policy::{
    AlwaysGrantAccessPolicy, ClarificationThenGrantAccessPolicy, DeferApprovalAccessPolicy,
    DeferClaimsAccessPolicy, DeferInteractionAccessPolicy,
};
#[cfg(all(feature = "policy", feature = "person-server"))]
pub use policy::{
    AlwaysGrantPersonPolicy, ClarificationThenGrantPersonPolicy, DeferInteractionPersonPolicy,
    FixedSubPersonPolicy,
};
#[cfg(all(feature = "policy", feature = "resource"))]
pub use policy::{AlwaysGrantResourcePolicy, DeferInteractionResourcePolicy};
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
pub use person_server::{AuthJwtMinter, TestAuthJwtMinter, mint_auth_jwt};
#[cfg(feature = "person-server")]
pub use person_server::{
    FederationConfig, FederationOutcome, PersonServerOutboundSigner, PersonTokenFlowOutcome,
    PersonTokenService, PersonTokenServiceError, PolicyPersonTokenService,
    federate_to_access_server, fulfill_token_exchange, verify_federated_auth_token,
};

#[cfg(all(feature = "access-server", feature = "access-server-axum"))]
pub use access_server::{AccessAuthJwtMinter, TestAccessAuthJwtMinter, mint_access_auth_jwt};
#[cfg(feature = "access-server")]
pub use access_server::{
    AccessTokenService, AccessTokenServiceError, PolicyAccessTokenService, build_access_context,
};

#[cfg(feature = "resource")]
pub use resource::{
    Ed25519ResourceTokenSigner, InMemoryOpaqueAccessStore, OpaqueAccessStore,
    PolicyResourceAccessService, ResourceAccessConfig, ResourceAccessMode, ResourceAccessPolicy,
    ResourceAccessPolicyService, ResourceAccessService, ResourceAccessServiceError,
    ResourceConsentFlowOutcome, ResourcePollOutcome, ResourceTokenOptions, ResourceTokenSigner,
    create_resource_token,
};

#[cfg(feature = "access-server-axum")]
pub use server_axum::{
    AccessServerConfig, AccessServerState, access_jwks_handler, access_metadata_handler,
    access_pending_poll_handler, access_pending_post_handler, access_token_exchange_handler,
};
#[cfg(any(
    feature = "person-server-axum",
    feature = "access-server-axum",
    feature = "resource-axum"
))]
pub use server_axum::{InternalServiceError, PendingResumeInput, polling_status};
#[cfg(feature = "person-server-axum")]
pub use server_axum::{
    PersonServerConfig, PersonServerState, pending_clarification_post_handler,
    pending_poll_handler, pending_post_handler, person_jwks_handler, person_metadata_handler,
    token_exchange_deferred_handler, token_exchange_handler,
};
#[cfg(feature = "resource-axum")]
pub use server_axum::{
    ResourceAuthLayer, ResourceServerState, VerifiedAAuthToken, resource_pending_poll_handler,
};
