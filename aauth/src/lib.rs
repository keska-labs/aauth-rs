//! Rust implementation of the [AAuth authorization protocol](https://github.com/dickhardt/AAuth).
//!
//! # Features
//!
//! Protocol-wide modules (`error`, `protocol`, `jwt`, `signature`, …) are always available.
//! Enable role-specific features to compile only what you need:
//!
//! - `agent` — agent runtime (transport-agnostic state machine and options)
//! - `person-server` — Person Server service trait
//! - `access-server` — Access Server service trait
//! - `resource` — Resource Server consent service trait
//! - `resource-verify` — resource token verification only (used by `person-server` and `aauth-reqwest`'s `verify`)
//! - `full` — all roles and agent (matches `default`)
//!
//! For axum HTTP adapters (handlers, `ResourceAuthLayer`), use the companion
//! crate `aauth-axum`. For the reqwest agent client (`AgentMiddleware`), use
//! `aauth-reqwest`. For batteries-included policy + pending store services, use
//! `aauth-policy`.
//!
//! Role services and deferred wire types live under their modules
//! (`person_server`, `access_server`, `resource`, `deferred`). Spec wire
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
pub use deferred::{AuthTokenFlowOutcome, AuthTokenPollOutcome, poll_outcome_from_snapshot};
#[cfg(feature = "deferred")]
pub use deferred::{
    DEFAULT_PENDING_TTL_SECS, DeferCreated, DeferRequirement, DeferWaiting, PaymentRequiredDefer,
    PendingInput, PendingOutcome, PendingSnapshot, generate_pending_id, parse_pending_post_body,
    pending_location,
};
#[cfg(feature = "deferred-http")]
pub use deferred::{
    OutboundSignatureProvider, ParsedDeferred, ServerPollOptions, ServerPollOutcome,
    parse_auth_token_response, parse_deferred_response, poll_pending_http, post_pending_input,
    resolve_deferred_location,
};

#[cfg(feature = "resource-verify")]
pub use resource_verify::{
    VerifyResourceTokenOptions, VerifyTokenOptions, resolve_resource_token_audience,
    verify_auth_token_binding, verify_client_auth_token, verify_resource_challenge,
    verify_resource_token, verify_token,
};

#[cfg(feature = "person-server")]
pub use person_server::{
    FederationOutcome, PersonAuthJwtMinter, PersonServerConfig, PersonServerOutboundSigner,
    PersonTokenContext, PersonTokenFlowOutcome, PersonTokenService, TestPersonAuthJwtMinter,
    federate_to_access_server, mint_person_auth_jwt, verify_federated_auth_token,
    verify_person_token_request,
};

#[cfg(feature = "access-server")]
pub use access_server::{
    AccessAuthJwtMinter, AccessServerConfig, AccessTokenContext, AccessTokenService,
    TestAccessAuthJwtMinter, build_access_context, mint_access_auth_jwt,
};

#[cfg(feature = "resource")]
pub use resource::{
    Ed25519ResourceTokenSigner, NoResourceAccessService, ResourceAccessConfig,
    ResourceAccessContext, ResourceAccessMode, ResourceAccessService, ResourceConsentFlowOutcome,
    ResourceInteractionContext, ResourceInteractionProvider, ResourcePollOutcome,
    ResourceTokenOptions, ResourceTokenSigner, create_resource_token,
};
