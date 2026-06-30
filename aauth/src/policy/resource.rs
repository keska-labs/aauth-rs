use crate::deferred::PendingInput;
use crate::jwt::AgentClaims;

use super::decision::ResourceConsentDecision;
use super::error::PolicyError;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ResourceAccessContext {
    pub resource_url: String,
    pub agent_claims: AgentClaims,
    pub scope: Option<String>,
}

#[async_trait::async_trait]
pub trait ResourceConsentPolicy: Send + Sync + Clone {
    async fn evaluate(
        &self,
        ctx: &ResourceAccessContext,
    ) -> Result<ResourceConsentDecision, PolicyError>;

    async fn resume(
        &self,
        ctx: &ResourceAccessContext,
        input: PendingInput,
    ) -> Result<ResourceConsentDecision, PolicyError>;
}
