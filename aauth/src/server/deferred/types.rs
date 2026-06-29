use serde::{Deserialize, Serialize};

use crate::jwt::{AgentClaims, ResourceClaims};
use crate::types::{
    AAuthChallenge, AAuthProtocolError, PendingStatus, TokenExchangeRequest, TokenResponseBody,
};

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

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum PendingKind {
    PersonToken,
    AccessToken,
    ResourceAccess,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct FederationPendingState {
    pub access_server_url: String,
    pub as_pending_url: String,
}

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

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ResourcePendingContext {
    pub resource_url: String,
    pub agent_claims: AgentClaims,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub scope: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum PendingContext {
    Person(PersonPendingContext),
    Access(AccessPendingContext),
    Resource(ResourcePendingContext),
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PendingRecord {
    pub id: String,
    pub created_at: u64,
    pub expires_at: u64,
    pub kind: PendingKind,
    pub context: PendingContext,
    pub snapshot: PendingSnapshot,
}

impl PendingRecord {
    pub fn new(
        id: String,
        kind: PendingKind,
        context: PendingContext,
        snapshot: PendingSnapshot,
        ttl_secs: u64,
    ) -> Self {
        let created_at = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs();
        Self {
            id,
            created_at,
            expires_at: created_at + ttl_secs,
            kind,
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
