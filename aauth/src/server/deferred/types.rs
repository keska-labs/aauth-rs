use serde::{Deserialize, Serialize};

use crate::jwt::{AgentClaims, ResourceClaims};
use crate::types::{AAuthProtocolError, TokenExchangeRequest, TokenResponseBody};

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum DeferRequirement {
    Interaction { url: String, code: String },
    Clarification { question: String, timeout: Option<u64> },
    Claims { required_claims: Vec<String> },
    Approval,
    Payment { location: String },
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum PendingStatus {
    Pending,
    Interacting,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum PendingOutcome {
    AuthToken(TokenResponseBody),
    OpaqueAccess(String),
    Error(AAuthProtocolError),
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PendingSnapshot {
    pub status: PendingStatus,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub requirement: Option<DeferRequirement>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub outcome: Option<PendingOutcome>,
}

impl PendingSnapshot {
    pub fn waiting(requirement: DeferRequirement) -> Self {
        Self {
            status: PendingStatus::Pending,
            requirement: Some(requirement),
            outcome: None,
        }
    }

    pub fn complete(outcome: PendingOutcome) -> Self {
        Self {
            status: PendingStatus::Pending,
            requirement: None,
            outcome: Some(outcome),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ClaimsSubmission {
    pub sub: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub email: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub tenant: Option<String>,
    #[serde(flatten)]
    pub extra: std::collections::HashMap<String, serde_json::Value>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum PendingInput {
    ClarificationResponse(String),
    ClaimsSubmission(ClaimsSubmission),
    InteractionCompleted,
    Cancelled,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum PendingKind {
    PersonToken,
    AccessToken,
    ResourceAccess,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PersonPendingContext {
    pub person_server_url: String,
    pub resource_url: String,
    pub agent_claims: AgentClaims,
    pub resource_claims: ResourceClaims,
    pub exchange_request: TokenExchangeRequest,
    pub agent_token: String,
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
