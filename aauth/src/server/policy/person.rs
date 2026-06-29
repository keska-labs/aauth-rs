use crate::jwt::{AgentClaims, ResourceClaims};
use crate::server::deferred::PendingInput;
use crate::types::TokenExchangeRequest;

use super::decision::PersonTokenDecision;
use super::error::PolicyError;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PersonTokenContext {
    pub person_server_url: String,
    pub resource_url: String,
    pub agent_claims: AgentClaims,
    pub resource_claims: ResourceClaims,
    pub exchange_request: TokenExchangeRequest,
}

impl PersonTokenContext {
    pub fn audience_is_person_server(&self) -> bool {
        normalize_url(&self.resource_claims.aud) == normalize_url(&self.person_server_url)
    }
}

fn normalize_url(url: &str) -> String {
    url.trim_end_matches('/').to_string()
}

#[async_trait::async_trait]
pub trait PersonTokenPolicy: Send + Sync + Clone {
    async fn evaluate(&self, ctx: &PersonTokenContext) -> Result<PersonTokenDecision, PolicyError>;

    async fn resume(
        &self,
        ctx: &PersonTokenContext,
        input: PendingInput,
    ) -> Result<PersonTokenDecision, PolicyError>;
}
