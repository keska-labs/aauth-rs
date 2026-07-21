//! Test harness resource consent policies that dispatch to concrete reference policies.

use aauth::ResourceAccessContext;
use aauth_policy::{
    AlwaysGrantResourcePolicy, DeferInteractionResourcePolicy, PolicyError,
    ResourceConsentDecision, ResourceConsentPolicy,
};

#[derive(Clone)]
pub enum HarnessResourcePolicy {
    Grant(AlwaysGrantResourcePolicy),
    Defer(DeferInteractionResourcePolicy),
}

#[async_trait::async_trait]
impl ResourceConsentPolicy for HarnessResourcePolicy {
    async fn evaluate(
        &self,
        ctx: &ResourceAccessContext,
    ) -> Result<ResourceConsentDecision, PolicyError> {
        match self {
            Self::Grant(p) => p.evaluate(ctx).await,
            Self::Defer(p) => p.evaluate(ctx).await,
        }
    }

    async fn resume(
        &self,
        ctx: &ResourceAccessContext,
        input: aauth::PendingInput,
    ) -> Result<ResourceConsentDecision, PolicyError> {
        match self {
            Self::Grant(p) => p.resume(ctx, input).await,
            Self::Defer(p) => p.resume(ctx, input).await,
        }
    }
}
