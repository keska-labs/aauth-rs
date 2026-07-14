use serde::{Deserialize, Serialize};

use crate::error::AAuthError;
use crate::jwt::{AgentClaims, ResourceClaims};
use crate::protocol::{
    AAuthChallenge, AAuthProtocolError, ClaimsChallenge, ClaimsSubmission, ClarificationChallenge,
    PendingStatus, ResourceInteractionClaim, TokenExchangeRequest, TokenResponseBody,
    UpdatedTokenRequest,
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

impl crate::protocol::PendingBody {
    pub fn for_created(
        requirement: &DeferRequirement,
    ) -> Result<crate::protocol::PendingBody, AAuthError> {
        Self::for_waiting(requirement, PendingStatus::Pending)
    }

    pub fn for_waiting(
        requirement: &DeferRequirement,
        status: PendingStatus,
    ) -> Result<crate::protocol::PendingBody, AAuthError> {
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
                Ok(Self::Status(crate::protocol::PendingStatusBody { status }))
            }
            DeferRequirement::Payment { .. } => Err(AAuthError::Message(
                "payment defer uses 402, not pending JSON body".into(),
            )),
        }
    }
}

impl From<crate::protocol::PendingPostBody> for PendingInput {
    fn from(body: crate::protocol::PendingPostBody) -> Self {
        match body {
            crate::protocol::PendingPostBody::Clarification(r) => {
                Self::ClarificationResponse(r.clarification_response)
            }
            crate::protocol::PendingPostBody::Claims(c) => Self::ClaimsSubmission(c),
            crate::protocol::PendingPostBody::UpdatedToken(r) => Self::UpdatedToken(r),
            crate::protocol::PendingPostBody::InteractionCompleted(_) => Self::InteractionCompleted,
        }
    }
}

/// Parse POST body on a pending URL into agent input.
pub fn parse_pending_post_body(body: &[u8]) -> Result<PendingInput, AAuthError> {
    if body.is_empty() || body.iter().all(|b| b.is_ascii_whitespace()) {
        return Ok(PendingInput::InteractionCompleted);
    }
    let wire: crate::protocol::PendingPostBody =
        serde_json::from_slice(body).map_err(|e| AAuthError::Message(e.to_string()))?;
    Ok(wire.into())
}

/// Deferred `AAuth-Requirement` encoded for server-side pending state.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum DeferRequirement {
    Interaction {
        url: String,
        code: String,
    },
    Clarification {
        question: String,
        timeout: Option<u64>,
    },
    Claims {
        required_claims: Vec<String>,
    },
    Approval,
    Payment {
        location: String,
    },
}

impl DeferRequirement {
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
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum PendingOutcome {
    AuthToken(TokenResponseBody),
    OpaqueAccess(String),
    Error(AAuthProtocolError),
}

/// Snapshot of a pending request exposed via poll responses.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum PendingSnapshot {
    Waiting {
        status: PendingStatus,
        requirement: DeferRequirement,
    },
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

/// Agent input to a pending URL during deferred resolution.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum PendingInput {
    ClarificationResponse(String),
    ClaimsSubmission(ClaimsSubmission),
    UpdatedToken(UpdatedTokenRequest),
    InteractionCompleted,
    Cancelled,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct FederationPendingState {
    pub access_server_url: String,
    pub as_pending_url: String,
}

#[serde_with::apply(
    Option => #[serde(default, skip_serializing_if = "Option::is_none")],
)]
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PersonPendingContext {
    pub person_server_url: String,
    pub resource_url: String,
    pub agent_claims: AgentClaims,
    pub resource_claims: ResourceClaims,
    pub exchange_request: TokenExchangeRequest,
    pub agent_token: String,
    pub federation: Option<FederationPendingState>,
    /// Unresolved resource-initiated interaction claim from the resource token.
    pub resource_interaction: Option<ResourceInteractionClaim>,
    /// PS-local interaction code (`XXXX-XXXX`) for pending lookup.
    pub ps_interaction_code: Option<String>,
    /// Whether the PS interaction code has been consumed (single-use).
    pub interaction_code_consumed: bool,
}

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

#[serde_with::apply(
    Option => #[serde(default, skip_serializing_if = "Option::is_none")],
)]
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ResourcePendingContext {
    pub resource_url: String,
    pub agent_claims: AgentClaims,
    pub scope: Option<String>,
}

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
