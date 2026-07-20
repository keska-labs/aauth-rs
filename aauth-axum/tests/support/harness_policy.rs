//! Test harness policies that dispatch to concrete reference policies.

use aauth::PendingInput;
use aauth::policy::{
    AlwaysGrantPersonPolicy, ClarificationThenGrantPersonPolicy, DeferInteractionPersonPolicy,
    PersonTokenContext, PersonTokenDecision, PersonTokenPolicy, PolicyError,
};

#[derive(Clone)]
pub enum HarnessPersonPolicy {
    Grant(AlwaysGrantPersonPolicy),
    Defer(DeferInteractionPersonPolicy<AlwaysGrantPersonPolicy>),
    Clarify(ClarificationThenGrantPersonPolicy),
}

#[async_trait::async_trait]
impl PersonTokenPolicy for HarnessPersonPolicy {
    async fn evaluate(&self, ctx: &PersonTokenContext) -> Result<PersonTokenDecision, PolicyError> {
        match self {
            Self::Grant(p) => p.evaluate(ctx).await,
            Self::Defer(p) => p.evaluate(ctx).await,
            Self::Clarify(p) => p.evaluate(ctx).await,
        }
    }

    async fn resume(
        &self,
        ctx: &PersonTokenContext,
        input: PendingInput,
    ) -> Result<PersonTokenDecision, PolicyError> {
        match self {
            Self::Grant(p) => p.resume(ctx, input).await,
            Self::Defer(p) => p.resume(ctx, input).await,
            Self::Clarify(p) => p.resume(ctx, input).await,
        }
    }
}
