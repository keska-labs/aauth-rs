use crate::jwt::{AgentClaims, ResourceClaims};
use crate::protocol::TokenExchangeRequest;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PersonTokenContext {
    pub person_server_url: String,
    pub resource_url: String,
    pub agent_claims: AgentClaims,
    pub resource_claims: ResourceClaims,
    pub exchange_request: TokenExchangeRequest,
}

use crate::http_util::normalize_server_url;

impl PersonTokenContext {
    pub fn audience_is_person_server(&self) -> bool {
        normalize_server_url(&self.resource_claims.aud)
            == normalize_server_url(&self.person_server_url)
    }
}
