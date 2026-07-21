use http::HeaderMap;

use crate::error::{DeferredError, HeaderError, Result};
use crate::protocol::AAuthChallenge;
use crate::protocol::{ClaimsChallenge, ClarificationChallenge, PendingStatus, TokenResponseBody};
use crate::signature::header_value;

use super::types::DeferRequirement;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ParsedDeferred {
    pub location: String,
    pub requirement: DeferRequirement,
}

fn resolve_deferred_location(base_url: &str, location: &str) -> String {
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
        return Err(DeferredError::UnexpectedStatus {
            expected: 202,
            got: status,
        }
        .into());
    }

    let location = header_value(headers, "location").ok_or(DeferredError::MissingLocation)?;
    let location = resolve_deferred_location(base_url, location);

    let requirement_header =
        header_value(headers, "aauth-requirement").ok_or(DeferredError::MissingRequirement)?;
    let challenge = AAuthChallenge::from_header(requirement_header)?;

    let requirement = defer_requirement_from(&challenge, body)?;

    Ok(ParsedDeferred {
        location,
        requirement,
    })
}

pub fn parse_auth_token_response(status: u16, body: &[u8]) -> Result<TokenResponseBody> {
    if status != 200 {
        return Err(DeferredError::UnexpectedStatus {
            expected: 200,
            got: status,
        }
        .into());
    }
    serde_json::from_slice(body)
        .map_err(DeferredError::Body)
        .map_err(Into::into)
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
                serde_json::from_slice(body).map_err(DeferredError::Body)?
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
                serde_json::from_slice(body).map_err(DeferredError::Body)?
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
        | crate::protocol::AAuthChallenge::AuthToken { .. } => Err(HeaderError::Invalid(
            "agent-token/auth-token requirements are not defer requirements".into(),
        )
        .into()),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use http::HeaderMap;

    use crate::deferred::DeferCreated;
    use crate::protocol::{AAuthChallenge, PendingBody};

    fn defer_created_parts(defer: &DeferCreated) -> (u16, HeaderMap, Vec<u8>) {
        let body = PendingBody::for_created(&defer.requirement).expect("pending body");
        let mut headers = HeaderMap::new();
        headers.insert("Location", defer.location.parse().expect("valid location"));
        headers.insert("Retry-After", "0".parse().expect("valid header"));
        headers.insert("Cache-Control", "no-store".parse().expect("valid header"));
        if let Ok(challenge) = defer.requirement.header_challenge() {
            let req = challenge.to_header();
            headers.insert(
                "AAuth-Requirement",
                req.parse().expect("valid requirement header"),
            );
        }
        headers.insert(
            "Content-Type",
            "application/json".parse().expect("valid content-type"),
        );
        (
            202,
            headers,
            serde_json::to_vec(&body).expect("serialize pending body"),
        )
    }

    #[test]
    fn round_trip_clarification_defer() {
        let requirement = DeferRequirement::Clarification {
            question: "Why?".into(),
            timeout: Some(60),
        };
        let defer = DeferCreated {
            location: "https://as.example/pending/abc".into(),
            requirement: requirement.clone(),
        };
        let (status, headers, body) = defer_created_parts(&defer);
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
        let defer = DeferCreated {
            location: "https://as.example/pending/x".into(),
            requirement: requirement.clone(),
        };
        let (status, headers, body) = defer_created_parts(&defer);
        let parsed =
            parse_deferred_response(status, &headers, &body, "https://as.example").unwrap();
        assert_eq!(parsed.requirement, requirement);
    }
}
