use std::sync::Arc;

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

impl<T: ResourceInteractionProvider + ?Sized> ResourceInteractionProvider for Arc<T> {
    fn interaction_for(
        &self,
        ctx: &ResourceInteractionContext,
    ) -> Option<ResourceInteractionClaim> {
        (**self).interaction_for(ctx)
    }
}

/// Marker provider when no resource-initiated interaction claim is needed.
#[derive(Clone, Copy, Debug, Default)]
pub struct NoResourceInteraction;

impl ResourceInteractionProvider for NoResourceInteraction {
    fn interaction_for(
        &self,
        _ctx: &ResourceInteractionContext,
    ) -> Option<ResourceInteractionClaim> {
        None
    }
}
