use serde::{Deserialize, Serialize};

use crate::error::AAuthError;
use crate::jwt::{AgentClaims, ResourceClaims};
use crate::types::{
    AAuthChallenge, AAuthProtocolError, ClaimsChallenge, ClarificationChallenge,
    ClarificationResponse, PendingStatus, TokenExchangeRequest, TokenResponseBody,
};

/// Initial `202` from token exchange, resource consent, or pending POST resume.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DeferCreated {
    pub location: String,
    pub requirement: DeferRequirement,
}

/// `202` while polling a pending URL (no new `Location`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DeferWaiting {
    pub status: PendingStatus,
    pub requirement: DeferRequirement,
}

/// `402 Payment Required` defer stub — poll `Location` after payment settlement.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PaymentRequiredDefer {
    pub location: String,
}

/// JSON body on a `202` pending / defer response.
#[derive(Debug, Clone, Serialize)]
#[serde(untagged)]
pub enum PendingBody {
    Status(PendingStatusBody),
    Clarification(ClarificationChallenge),
    Claims(ClaimsChallenge),
}

/// Status-only pending response body (`interaction` / `approval`).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct PendingStatusBody {
    pub status: PendingStatus,
}

impl PendingBody {
    pub fn for_created(requirement: &DeferRequirement) -> Result<Self, AAuthError> {
        Self::for_waiting(requirement, PendingStatus::Pending)
    }

    pub fn for_waiting(
        requirement: &DeferRequirement,
        status: PendingStatus,
    ) -> Result<Self, AAuthError> {
        match requirement {
            DeferRequirement::Clarification { question, timeout } => {
                Ok(Self::Clarification(ClarificationChallenge {
                    status,
                    clarification: question.clone(),
                    timeout: *timeout,
                    options: None,
                }))
            }
            DeferRequirement::Claims { required_claims } => Ok(Self::Claims(ClaimsChallenge {
                status,
                required_claims: required_claims.clone(),
            })),
            DeferRequirement::Interaction { .. } | DeferRequirement::Approval => {
                Ok(Self::Status(PendingStatusBody { status }))
            }
            DeferRequirement::Payment { .. } => Err(AAuthError::Message(
                "payment defer uses 402, not pending JSON body".into(),
            )),
        }
    }
}

/// Empty `{}` or omitted body = interaction completed on a pending URL.
#[derive(Debug, Clone, Deserialize)]
pub struct InteractionCompletedBody {}

/// Agent POST body on a pending URL (no wire discriminator in spec yet).
#[derive(Debug, Clone, Deserialize)]
#[serde(untagged)]
pub enum PendingPostBody {
    Clarification(ClarificationResponse),
    Claims(ClaimsSubmission),
    InteractionCompleted(InteractionCompletedBody),
}

impl From<PendingPostBody> for PendingInput {
    fn from(body: PendingPostBody) -> Self {
        match body {
            PendingPostBody::Clarification(r) => {
                Self::ClarificationResponse(r.clarification_response)
            }
            PendingPostBody::Claims(c) => Self::ClaimsSubmission(c),
            PendingPostBody::InteractionCompleted(_) => Self::InteractionCompleted,
        }
    }
}

/// Parse POST body on a pending URL into agent input.
///
/// Spec gap: no wire-level type tag on pending POST bodies yet — uses shape matching.
pub fn parse_pending_post_body(body: &[u8]) -> Result<PendingInput, AAuthError> {
    if body.is_empty() || body.iter().all(|b| b.is_ascii_whitespace()) {
        return Ok(PendingInput::InteractionCompleted);
    }
    let wire: PendingPostBody =
        serde_json::from_slice(body).map_err(|e| AAuthError::Message(e.to_string()))?;
    Ok(wire.into())
}

/// Deferred `AAuth-Requirement` encoded for server-side pending state.
///
/// Spec: https://github.com/dickhardt/AAuth/blob/main/draft-hardt-oauth-aauth-protocol.md#requirement-values
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum DeferRequirement {
    /// `requirement=interaction` with required `url` and `code` parameters.
    Interaction {
        /// Interaction URL. MUST use `https` with no query or fragment.
        url: String,
        /// Interaction code per the interaction code format rules.
        code: String,
    },
    /// `requirement=clarification` with optional response deadline.
    Clarification {
        /// Markdown clarification question.
        question: String,
        /// Seconds until the server times out the request.
        timeout: Option<u64>,
    },
    /// `requirement=claims` with required claim names.
    Claims {
        /// Claim names the recipient MUST provide (including directed `sub`).
        required_claims: Vec<String>,
    },
    /// `requirement=approval` — poll until a terminal response.
    Approval,
    /// `402 Payment Required` — poll `Location` after payment settlement.
    Payment {
        /// Pending URL to poll after payment.
        location: String,
    },
}

impl DeferRequirement {
    /// Header-only [`AAuthChallenge`] for this deferred requirement.
    ///
    /// Returns an error for [`DeferRequirement::Payment`], which uses `402` rather than
    /// `AAuth-Requirement`.
    pub fn header_challenge(&self) -> Result<AAuthChallenge, crate::error::AAuthError> {
        match self {
            Self::Interaction { url, code } => Ok(AAuthChallenge::Interaction {
                url: url.clone(),
                code: code.clone(),
            }),
            Self::Clarification { .. } => Ok(AAuthChallenge::Clarification),
            Self::Claims { .. } => Ok(AAuthChallenge::Claims),
            Self::Approval => Ok(AAuthChallenge::Approval),
            Self::Payment { .. } => Err(crate::error::AAuthError::Message(
                "payment defer uses 402, not AAuth-Requirement".into(),
            )),
        }
    }
}

/// Terminal or in-progress outcome stored for pending poll responses.
///
/// Spec: https://github.com/dickhardt/AAuth/blob/main/draft-hardt-oauth-aauth-protocol.md#deferred-responses
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum PendingOutcome {
    /// Direct grant (`200`) with an auth token.
    AuthToken(TokenResponseBody),
    /// Resource-managed opaque access token from `AAuth-Access`.
    OpaqueAccess(String),
    /// Terminal polling or token endpoint error.
    Error(AAuthProtocolError),
}

/// Snapshot of a pending request exposed via poll responses.
///
/// Spec: https://github.com/dickhardt/AAuth/blob/main/draft-hardt-oauth-aauth-protocol.md#pending-response
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum PendingSnapshot {
    /// Request is still waiting on a deferred requirement.
    Waiting {
        /// `"pending"` or `"interacting"`.
        status: PendingStatus,
        /// Active requirement while unresolved.
        requirement: DeferRequirement,
    },
    /// Terminal outcome once resolved.
    Complete(PendingOutcome),
}

impl PendingSnapshot {
    pub fn waiting(requirement: DeferRequirement) -> Self {
        Self::Waiting {
            status: PendingStatus::Pending,
            requirement,
        }
    }

    pub fn complete(outcome: PendingOutcome) -> Self {
        Self::Complete(outcome)
    }
}

/// Identity claims POSTed to a pending URL for `requirement=claims`.
///
/// Spec: https://github.com/dickhardt/AAuth/blob/main/draft-hardt-oauth-aauth-protocol.md#claims-required-requirement-claims
///
/// MUST include a directed user identifier as [`sub`](Self::sub). Unrecognized claim names SHOULD
/// be ignored by the recipient.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ClaimsSubmission {
    /// Directed user identifier for the resource.
    pub sub: String,
    /// Identity claim when requested by `required_claims`.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub email: Option<String>,
    /// Tenant identifier when requested by `required_claims`.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub tenant: Option<String>,
    /// Additional requested identity claims.
    #[serde(flatten)]
    pub extra: std::collections::HashMap<String, serde_json::Value>,
}

/// Agent input to a pending URL during deferred resolution.
///
/// Spec: https://github.com/dickhardt/AAuth/blob/main/draft-hardt-oauth-aauth-protocol.md#agent-response-to-clarification
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum PendingInput {
    /// POST `clarification_response` to answer a clarification.
    ClarificationResponse(String),
    /// POST requested identity claims for `requirement=claims`.
    ClaimsSubmission(ClaimsSubmission),
    /// Signal that the user completed an interaction.
    InteractionCompleted,
    /// DELETE the pending URL to withdraw the request.
    Cancelled,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct FederationPendingState {
    pub access_server_url: String,
    pub as_pending_url: String,
}

/// Resume state for a Person Server deferred token exchange.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PersonPendingContext {
    pub person_server_url: String,
    pub resource_url: String,
    pub agent_claims: AgentClaims,
    pub resource_claims: ResourceClaims,
    pub exchange_request: TokenExchangeRequest,
    pub agent_token: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub federation: Option<FederationPendingState>,
}

/// Resume state for an Access Server deferred token exchange.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AccessPendingContext {
    pub access_server_url: String,
    pub resource_url: String,
    pub person_server_url: String,
    pub agent_claims: AgentClaims,
    pub resource_claims: ResourceClaims,
    pub resource_token: String,
    pub agent_token: String,
}

/// Resume state for a resource-managed deferred access request.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ResourcePendingContext {
    pub resource_url: String,
    pub agent_claims: AgentClaims,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub scope: Option<String>,
}

/// Stored pending request with role-specific resume context.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PendingRecord<C> {
    pub id: String,
    pub created_at: u64,
    pub expires_at: u64,
    pub context: C,
    pub snapshot: PendingSnapshot,
}

pub type PersonPendingRecord = PendingRecord<PersonPendingContext>;
pub type AccessPendingRecord = PendingRecord<AccessPendingContext>;
pub type ResourcePendingRecord = PendingRecord<ResourcePendingContext>;

impl<C> PendingRecord<C> {
    pub fn new(id: String, context: C, snapshot: PendingSnapshot, ttl_secs: u64) -> Self {
        let created_at = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs();
        Self {
            id,
            created_at,
            expires_at: created_at + ttl_secs,
            context,
            snapshot,
        }
    }

    pub fn is_expired(&self) -> bool {
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs();
        now > self.expires_at
    }
}
