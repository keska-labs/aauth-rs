use aauth::PendingSnapshot;
use aauth::jwt::{AgentClaims, ResourceClaims};
use aauth::protocol::{ResourceInteractionClaim, TokenExchangeRequest};
use serde::{Deserialize, Serialize};

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
