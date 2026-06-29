use crate::jwt::AgentClaims;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AudienceError {
    NoAudience,
}

impl std::fmt::Display for AudienceError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::NoAudience => f.write_str(
                "cannot determine resource token audience: no access server, no agent ps claim, and no fallback",
            ),
        }
    }
}

impl std::error::Error for AudienceError {}

/// Resolve resource token `aud` per spec `#requirement-auth-token`.
pub fn resolve_resource_token_audience(
    agent: &AgentClaims,
    access_server_url: Option<&str>,
    person_server_fallback: Option<&str>,
) -> Result<String, AudienceError> {
    if let Some(as_url) = access_server_url {
        return Ok(as_url.to_string());
    }
    if let Some(ps) = &agent.ps {
        return Ok(ps.clone());
    }
    if let Some(fallback) = person_server_fallback {
        return Ok(fallback.to_string());
    }
    Err(AudienceError::NoAudience)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::jwt::{AgentClaims, CnfClaim, OkpJwk};

    fn agent(ps: Option<&str>) -> AgentClaims {
        AgentClaims {
            iss: "https://agent.example".into(),
            dwk: "aauth-agent.json".into(),
            sub: "aauth:test@example.com".into(),
            jti: "jti".into(),
            cnf: CnfClaim {
                jwk: OkpJwk {
                    kty: "OKP".into(),
                    crv: "Ed25519".into(),
                    x: "x".into(),
                    kid: None,
                },
            },
            iat: 0,
            exp: 9999999999,
            ps: ps.map(str::to_string),
        }
    }

    #[test]
    fn access_server_takes_priority() {
        assert_eq!(
            resolve_resource_token_audience(
                &agent(Some("https://ps.example")),
                Some("https://as.example"),
                None,
            )
            .unwrap(),
            "https://as.example"
        );
    }

    #[test]
    fn ps_claim_used_when_no_as() {
        assert_eq!(
            resolve_resource_token_audience(&agent(Some("https://ps.example")), None, None,)
                .unwrap(),
            "https://ps.example"
        );
    }

    #[test]
    fn fallback_for_tests() {
        assert_eq!(
            resolve_resource_token_audience(&agent(None), None, Some("https://ps.example"))
                .unwrap(),
            "https://ps.example"
        );
    }

    #[test]
    fn none_when_unresolvable() {
        assert!(resolve_resource_token_audience(&agent(None), None, None).is_err());
    }
}
