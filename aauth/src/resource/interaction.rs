use crate::jwt::AgentClaims;
use crate::protocol::ResourceInteractionClaim;

/// Context passed to [`ResourceInteractionProvider::interaction_for`].
#[derive(Debug, Clone)]
pub struct ResourceInteractionContext {
    pub resource_url: String,
    pub agent: AgentClaims,
    pub agent_jkt: String,
}

/// Optional hook for PS-asserted resources to embed a resource-initiated interaction claim.
pub trait ResourceInteractionProvider: Send + Sync {
    fn interaction_for(&self, ctx: &ResourceInteractionContext)
    -> Option<ResourceInteractionClaim>;
}
