//! Test harness access policies that dispatch to concrete reference policies.

use aauth::{
    AccessTokenContext, AccessTokenPolicy, AlwaysGrantAccessPolicy,
    ClarificationThenGrantAccessPolicy, DeferInteractionAccessPolicy, PolicyError,
    TokenPolicyDecision,
};

#[derive(Clone)]
pub enum HarnessAccessPolicy {
    Grant(AlwaysGrantAccessPolicy),
    Clarify(ClarificationThenGrantAccessPolicy),
    Defer(DeferInteractionAccessPolicy<AlwaysGrantAccessPolicy>),
}

#[async_trait::async_trait]
impl AccessTokenPolicy for HarnessAccessPolicy {
    async fn evaluate(&self, ctx: &AccessTokenContext) -> Result<TokenPolicyDecision, PolicyError> {
        match self {
            Self::Grant(p) => p.evaluate(ctx).await,
            Self::Clarify(p) => p.evaluate(ctx).await,
            Self::Defer(p) => p.evaluate(ctx).await,
        }
    }

    async fn resume(
        &self,
        ctx: &AccessTokenContext,
        input: aauth::PendingInput,
    ) -> Result<TokenPolicyDecision, PolicyError> {
        match self {
            Self::Grant(p) => p.resume(ctx, input).await,
            Self::Clarify(p) => p.resume(ctx, input).await,
            Self::Defer(p) => p.resume(ctx, input).await,
        }
    }
}
