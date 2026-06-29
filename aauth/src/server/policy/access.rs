use crate::jwt::{AgentClaims, ResourceClaims};
use crate::server::deferred::PendingInput;

use super::decision::TokenPolicyDecision;
use super::error::PolicyError;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AccessTokenContext {
    pub access_server_url: String,
    pub resource_url: String,
    pub person_server_url: String,
    pub agent_claims: AgentClaims,
    pub resource_claims: ResourceClaims,
    pub resource_token: String,
    pub agent_token: String,
}

#[async_trait::async_trait]
pub trait AccessTokenPolicy: Send + Sync + Clone {
    async fn evaluate(&self, ctx: &AccessTokenContext) -> Result<TokenPolicyDecision, PolicyError>;

    async fn resume(
        &self,
        ctx: &AccessTokenContext,
        input: PendingInput,
    ) -> Result<TokenPolicyDecision, PolicyError>;
}
