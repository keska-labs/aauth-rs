use crate::jwt::AgentClaims;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ResourceAccessContext {
    pub resource_url: String,
    pub agent_claims: AgentClaims,
    pub scope: Option<String>,
}
