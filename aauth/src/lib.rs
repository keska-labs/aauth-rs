#![doc = include_str!("../README.md")]

pub mod error;
pub mod http_util;
pub mod interaction_code;
pub mod jwt;
pub mod keys;
pub mod metadata;
pub mod protocol;

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
    AgentJwtMinter, DynKeyMaterialProvider, KeyMaterialProvider, LocalKeyMaterialProvider,
    StaticKeyMaterialProvider, TestAgentJwtMinter,
};
#[cfg(feature = "agent")]
pub use agent::resolve::{agent_jwt_from_signature_key, resolve_person_server_url};
pub use error::{
    AAuthError, AgentAuthError, DeferredError, HeaderError, IntoAauthProtocol, JwtError,
    MetadataError, ResourceTokenError, Result, SignatureError, VerifyError, VerifyReason,
};
pub use httpsig_key::SignatureErrorHeader;
pub use interaction_code::{canonicalize_code, generate_code};
pub use jwt::{
    ActClaim, AgentClaims, AuthClaims, CnfClaim, ParsedToken, PublicJwk, ResourceClaims,
    ResourceInteractionClaim, SigningJwk, jwk_set_from_public, jwk_thumbprint,
};
pub use keys::{Ed25519KeyPair, SigningKey, TestKeys};
pub use metadata::{
    AbsentMetadataFetcher, DynMetadataFetcher, LocalMetadataFetcher, MetadataFetcher,
    StaticMetadataFetcher,
};

// Common protocol prelude used across roles (not the full governance surface).
pub use protocol::{
    AAUTH_ACCESS, AAUTH_ACCESS_NAME, AAUTH_CAPABILITIES, AAUTH_CAPABILITIES_NAME, AAUTH_MISSION,
    AAUTH_MISSION_NAME, AAUTH_REQUIREMENT, AAUTH_REQUIREMENT_NAME, AAuthChallenge, AAuthErrorCode,
    AAuthProtocolError, AccessServerMetadata, AccessTokenExchangeRequest, AgentOkResponse,
    AgentProviderMetadata, AuthOkResponse, Capability, ClaimsChallenge, ClaimsSubmission,
    ClarificationChallenge, ClarificationResponse, JwksDocument, JwtTyp, KeyMaterial, Mission,
    PREFER, PREFER_NAME, ParseStrError, PendingBody, PendingPostBody, PendingStatus,
    PendingStatusBody, PersonServerMetadata, RequirementLevel, SIGNATURE, SIGNATURE_ERROR,
    SIGNATURE_ERROR_NAME, SIGNATURE_INPUT, SIGNATURE_INPUT_NAME, SIGNATURE_KEY, SIGNATURE_KEY_NAME,
    SIGNATURE_NAME, SignatureKey, SignatureKeyHwk, SignatureKeyJktJwt, SignatureKeyJwt,
    TokenExchangeRequest, TokenResponseBody, UpdatedTokenRequest, is_token68,
    is_valid_agent_identifier, is_valid_server_identifier, parse_aauth_access_header,
    parse_aauth_credential,
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
};

#[cfg(feature = "resource-verify")]
pub use resource_verify::{
    VerifyResourceTokenOptions, VerifyTokenOptions, resolve_resource_token_audience,
    verify_auth_token_binding, verify_client_auth_token, verify_resource_challenge,
    verify_resource_token, verify_token,
};

#[cfg(feature = "person-server")]
pub use person_server::{
    DynPersonTokenService, FederationOutcome, LocalPersonTokenService, PersonAuthJwtMinter,
    PersonServerConfig, PersonServerOutboundSigner, PersonTokenContext, PersonTokenFlowOutcome,
    PersonTokenService, TestPersonAuthJwtMinter, verify_federated_auth_token,
};

#[cfg(feature = "access-server")]
pub use access_server::{
    AccessAuthJwtMinter, AccessServerConfig, AccessTokenContext, AccessTokenService,
    DynAccessTokenService, LocalAccessTokenService, TestAccessAuthJwtMinter,
};

#[cfg(feature = "resource")]
pub use resource::{
    DynResourceAccessService, DynResourceTokenSigner, Ed25519ResourceTokenSigner,
    LocalResourceAccessService, LocalResourceTokenSigner, NoResourceAccessService,
    NoResourceInteraction, ResourceAccessConfig, ResourceAccessContext, ResourceAccessMode,
    ResourceAccessService, ResourceConsentFlowOutcome, ResourceInteractionContext,
    ResourceInteractionProvider, ResourcePollOutcome, ResourceTokenOptions, ResourceTokenSigner,
};
