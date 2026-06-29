use http::HeaderMap;

use crate::error::{AAuthError, Result};
use crate::headers::parse_aauth_requirement;
use crate::types::{RequirementLevel, TokenResponseBody};

use super::types::DeferRequirement;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ParsedDeferred {
    pub location: String,
    pub requirement: DeferRequirement,
}

pub fn resolve_deferred_location(base_url: &str, location: &str) -> String {
    if location.starts_with("http://") || location.starts_with("https://") {
        location.to_string()
    } else {
        url::Url::parse(base_url)
            .and_then(|b| b.join(location.trim_start_matches('/')))
            .map(|u| u.to_string())
            .unwrap_or_else(|_| location.to_string())
    }
}

pub fn parse_deferred_response(
    status: u16,
    headers: &HeaderMap,
    body: &[u8],
    base_url: &str,
) -> Result<ParsedDeferred> {
    if status != 202 {
        return Err(AAuthError::Message(format!(
            "expected 202 Accepted, got {status}"
        )));
    }

    let location = header_value(headers, "location")
        .ok_or_else(|| AAuthError::Message("202 response missing Location header".into()))?;
    let location = resolve_deferred_location(base_url, location);

    let requirement_header = header_value(headers, "aauth-requirement").ok_or_else(|| {
        AAuthError::Message("202 response missing AAuth-Requirement header".into())
    })?;
    let challenge = parse_aauth_requirement(requirement_header)?;

    let json_body: Option<serde_json::Value> = if body.is_empty() {
        None
    } else {
        serde_json::from_slice(body).ok()
    };

    let requirement = map_challenge_to_defer(&challenge, json_body.as_ref())?;

    Ok(ParsedDeferred {
        location,
        requirement,
    })
}

pub fn parse_auth_token_response(status: u16, body: &[u8]) -> Result<TokenResponseBody> {
    if status != 200 {
        return Err(AAuthError::Message(format!(
            "expected 200 OK for auth token, got {status}"
        )));
    }
    serde_json::from_slice(body).map_err(|e| AAuthError::Message(e.to_string()))
}

fn map_challenge_to_defer(
    challenge: &crate::types::AAuthChallenge,
    body: Option<&serde_json::Value>,
) -> Result<DeferRequirement> {
    match challenge.requirement {
        RequirementLevel::Clarification => {
            let question = body
                .and_then(|v| v.get("clarification"))
                .and_then(|v| v.as_str())
                .unwrap_or("Please clarify your request")
                .to_string();
            let timeout = body.and_then(|v| v.get("timeout")).and_then(|v| v.as_u64());
            Ok(DeferRequirement::Clarification { question, timeout })
        }
        RequirementLevel::Claims => {
            let required_claims = body
                .and_then(|v| v.get("required_claims"))
                .and_then(|v| v.as_array())
                .map(|arr| {
                    arr.iter()
                        .filter_map(|v| v.as_str().map(str::to_string))
                        .collect()
                })
                .unwrap_or_default();
            Ok(DeferRequirement::Claims { required_claims })
        }
        RequirementLevel::Interaction => {
            let url = challenge
                .url
                .clone()
                .ok_or_else(|| AAuthError::Message("interaction defer missing url".into()))?;
            let code = challenge
                .code
                .clone()
                .ok_or_else(|| AAuthError::Message("interaction defer missing code".into()))?;
            Ok(DeferRequirement::Interaction { url, code })
        }
        RequirementLevel::Approval => Ok(DeferRequirement::Approval),
        RequirementLevel::AgentToken | RequirementLevel::AuthToken => Err(AAuthError::Message(
            "agent-token/auth-token requirements are not defer requirements".into(),
        )),
    }
}

fn header_value<'a>(headers: &'a HeaderMap, name: &str) -> Option<&'a str> {
    headers.get(name).and_then(|v| v.to_str().ok()).or_else(|| {
        headers.iter().find_map(|(k, v)| {
            if k.as_str().eq_ignore_ascii_case(name) {
                v.to_str().ok()
            } else {
                None
            }
        })
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::server::deferred::build_accepted;

    #[test]
    fn round_trip_clarification_defer() {
        let requirement = DeferRequirement::Clarification {
            question: "Why?".into(),
            timeout: Some(60),
        };
        let accepted = build_accepted("https://as.example/pending/abc", &requirement).unwrap();
        let body = accepted.body.to_string();
        let parsed = parse_deferred_response(
            202,
            &accepted.headers,
            body.as_bytes(),
            "https://as.example",
        )
        .unwrap();
        assert_eq!(parsed.location, "https://as.example/pending/abc");
        assert_eq!(parsed.requirement, requirement);
    }

    #[test]
    fn round_trip_interaction_defer() {
        let requirement = DeferRequirement::Interaction {
            url: "https://as.example/interact".into(),
            code: "AB-CD".into(),
        };
        let accepted = build_accepted("https://as.example/pending/x", &requirement).unwrap();
        let parsed = parse_deferred_response(
            202,
            &accepted.headers,
            accepted.body.to_string().as_bytes(),
            "https://as.example",
        )
        .unwrap();
        assert_eq!(parsed.requirement, requirement);
    }
}
