use crate::jwt::{AgentClaims, ResourceClaims};

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
