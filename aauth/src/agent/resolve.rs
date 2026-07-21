use crate::error::{AgentAuthError, Result};
use crate::jwt::AgentClaims;
use crate::protocol::SignatureKey;

/// Resolve the Person Server URL for token exchange.
///
/// Prefers explicit configuration; otherwise uses the `ps` claim from the agent JWT.
pub fn resolve_person_server_url(configured: Option<&str>, agent_jwt: &str) -> Result<String> {
    if let Some(url) = configured {
        return Ok(url.to_string());
    }
    let claims = decode_agent_claims_unverified(agent_jwt)?;
    claims
        .ps
        .ok_or(AgentAuthError::PersonServerUnresolved)
        .map_err(Into::into)
}

pub fn agent_jwt_from_signature_key(signature_key: &SignatureKey) -> Result<&str> {
    match signature_key {
        SignatureKey::Jwt(j) => Ok(&j.jwt),
        SignatureKey::JktJwt(j) => Ok(&j.jwt),
        SignatureKey::Hwk(_) => Err(AgentAuthError::HwkUnsupported.into()),
    }
}

fn decode_agent_claims_unverified(jwt: &str) -> Result<AgentClaims> {
    use crate::jwt::VerifiedToken;
    match VerifiedToken::decode_unverified(jwt)? {
        VerifiedToken::Agent(claims) => Ok(claims),
        VerifiedToken::Auth(_) => Err(AgentAuthError::ExpectedAgentJwt.into()),
    }
}
