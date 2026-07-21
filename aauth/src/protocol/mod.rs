//! Cross-entity AAuth wire types (HTTP bodies, headers, JWT payloads, metadata).
//!
//! Sourced from `docs/specs/draft-hardt-oauth-aauth-protocol.md`.

pub mod audit;
pub mod authorization;
pub mod common;
pub mod error;
pub mod headers;
pub mod interaction;
pub mod jwt;
pub mod metadata;
pub mod mission;
pub mod pending;
pub mod permission;
pub mod signature;
pub mod token_exchange;

pub use audit::AuditRequest;
pub use authorization::{
    AgentOkResponse, AuthOkResponse, AuthorizationGrantedResponse, AuthorizationRequest,
    ResourceTokenResponse,
};
pub use common::{Capability, Mission, ParseStrError, PendingStatus, RequirementLevel};
pub use error::{AAuthErrorCode, AAuthProtocolError};
pub use headers::{
    AAUTH_ACCESS, AAUTH_ACCESS_NAME, AAUTH_CAPABILITIES, AAUTH_CAPABILITIES_NAME, AAUTH_MISSION,
    AAUTH_MISSION_NAME, AAUTH_REQUIREMENT, AAUTH_REQUIREMENT_NAME, AAuthChallenge, PREFER,
    PREFER_NAME, SIGNATURE, SIGNATURE_INPUT, SIGNATURE_INPUT_NAME, SIGNATURE_KEY,
    SIGNATURE_KEY_NAME, SIGNATURE_NAME,
};
pub use interaction::{
    InteractionQuestionResponse, InteractionRequest, InteractionType, MissionStatusError,
};
pub use jwt::{
    ActClaim, AgentClaims, AuthClaims, CnfClaim, JwtTyp, PublicJwk, ResourceClaims,
    ResourceInteractionClaim, SigningJwk,
};
pub use metadata::{
    AccessServerMetadata, AgentProviderMetadata, JwksDocument, PersonServerMetadata,
    ResourceAccessModeWire, ResourceServerMetadata, RevocationRequest,
};
pub use mission::{MissionBlob, MissionProposalRequest, MissionTool};
pub use pending::{
    ClaimsChallenge, ClaimsSubmission, ClarificationChallenge, ClarificationResponse,
    InteractionCompletedBody, PaymentRequiredBody, PendingBody, PendingPostBody, PendingStatusBody,
    UpdatedTokenRequest,
};
pub use permission::{PermissionDecision, PermissionRequest, PermissionResponse};
pub use signature::{
    KeyMaterial, SignatureKey, SignatureKeyHwk, SignatureKeyJktJwt, SignatureKeyJwt,
};
pub use token_exchange::{AccessTokenExchangeRequest, TokenExchangeRequest, TokenResponseBody};
