use http::HeaderMap;

use crate::error::{AAuthError, Result};
use crate::protocol::parse_aauth_requirement;
use crate::protocol::{ClaimsChallenge, ClarificationChallenge, PendingStatus, TokenResponseBody};

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

    let requirement = defer_requirement_from(&challenge, body)?;

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

fn defer_requirement_from(
    challenge: &crate::protocol::AAuthChallenge,
    body: &[u8],
) -> Result<DeferRequirement> {
    match challenge {
        crate::protocol::AAuthChallenge::Clarification => {
            let c: ClarificationChallenge = if body.is_empty() {
                ClarificationChallenge {
                    status: PendingStatus::Pending,
                    clarification: "Please clarify your request".into(),
                    timeout: None,
                    options: None,
                }
            } else {
                serde_json::from_slice(body).map_err(|e| AAuthError::Message(e.to_string()))?
            };
            Ok(DeferRequirement::Clarification {
                question: c.clarification,
                timeout: c.timeout,
            })
        }
        crate::protocol::AAuthChallenge::Claims => {
            let c: ClaimsChallenge = if body.is_empty() {
                ClaimsChallenge {
                    status: PendingStatus::Pending,
                    required_claims: vec![],
                }
            } else {
                serde_json::from_slice(body).map_err(|e| AAuthError::Message(e.to_string()))?
            };
            Ok(DeferRequirement::Claims {
                required_claims: c.required_claims,
            })
        }
        crate::protocol::AAuthChallenge::Interaction { url, code } => {
            Ok(DeferRequirement::Interaction {
                url: url.clone(),
                code: code.clone(),
            })
        }
        crate::protocol::AAuthChallenge::Approval => Ok(DeferRequirement::Approval),
        crate::protocol::AAuthChallenge::AgentToken
        | crate::protocol::AAuthChallenge::AuthToken { .. } => Err(AAuthError::Message(
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
    use axum::response::IntoResponse;

    use crate::deferred::DeferCreated;

    fn response_parts_sync(response: axum::response::Response) -> (u16, HeaderMap, Vec<u8>) {
        let rt = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .expect("runtime");
        rt.block_on(async {
            let status = response.status().as_u16();
            let headers = response.headers().clone();
            let body = axum::body::to_bytes(response.into_body(), usize::MAX)
                .await
                .expect("bytes");
            (status, headers, body.to_vec())
        })
    }

    #[test]
    fn round_trip_clarification_defer() {
        let requirement = DeferRequirement::Clarification {
            question: "Why?".into(),
            timeout: Some(60),
        };
        let response = DeferCreated {
            location: "https://as.example/pending/abc".into(),
            requirement: requirement.clone(),
        }
        .into_response();
        let (status, headers, body) = response_parts_sync(response);
        let parsed =
            parse_deferred_response(status, &headers, &body, "https://as.example").unwrap();
        assert_eq!(parsed.location, "https://as.example/pending/abc");
        assert_eq!(parsed.requirement, requirement);
    }

    #[test]
    fn round_trip_interaction_defer() {
        let requirement = DeferRequirement::Interaction {
            url: "https://as.example/interact".into(),
            code: "AB-CD".into(),
        };
        let response = DeferCreated {
            location: "https://as.example/pending/x".into(),
            requirement: requirement.clone(),
        }
        .into_response();
        let (status, headers, body) = response_parts_sync(response);
        let parsed =
            parse_deferred_response(status, &headers, &body, "https://as.example").unwrap();
        assert_eq!(parsed.requirement, requirement);
    }
}
