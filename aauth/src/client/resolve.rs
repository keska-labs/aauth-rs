use crate::error::{AAuthError, Result};
use crate::jwt::{AgentClaims, decode_resource_token_unverified};
use crate::types::SignatureKey;

/// Resolve the Person Server URL for token exchange.
///
/// Prefers explicit configuration; otherwise uses the `ps` claim from the agent JWT.
pub fn resolve_person_server_url(
    configured: Option<&str>,
    agent_jwt: &str,
) -> Result<String> {
    if let Some(url) = configured {
        return Ok(url.to_string());
    }
    person_server_from_agent_jwt(agent_jwt)
}

pub fn person_server_from_agent_jwt(agent_jwt: &str) -> Result<String> {
    let claims = decode_agent_claims_unverified(agent_jwt)?;
    claims.ps.ok_or_else(|| {
        AAuthError::Message(
            "auth-token challenge received but no person_server_url configured and agent token has no ps claim".into(),
        )
    })
}

pub fn agent_jwt_from_signature_key(signature_key: &SignatureKey) -> Result<&str> {
    match signature_key {
        SignatureKey::Jwt(j) => Ok(&j.jwt),
        SignatureKey::JktJwt(j) => Ok(&j.jwt),
        SignatureKey::Hwk(_) => Err(AAuthError::Message(
            "hwk signature key cannot supply agent JWT for PS resolution".into(),
        )),
    }
}

fn decode_agent_claims_unverified(jwt: &str) -> Result<AgentClaims> {
    use crate::jwt::VerifiedToken;
    match VerifiedToken::decode_unverified(jwt)? {
        VerifiedToken::Agent(claims) => Ok(claims),
        VerifiedToken::Auth(_) => Err(AAuthError::Message(
            "expected agent JWT for person server resolution".into(),
        )),
    }
}

/// Read the `aud` claim from a resource token without signature verification.
pub fn resource_token_audience_unverified(resource_token: &str) -> Result<String> {
    Ok(decode_resource_token_unverified(resource_token)?.aud)
}
