use crate::error::{AAuthError, Result};
use crate::types::{AAuthChallenge, Capability, Mission, RequirementLevel};

pub fn build_capabilities_header(capabilities: &[Capability]) -> String {
    capabilities
        .iter()
        .map(|c| c.as_str())
        .collect::<Vec<_>>()
        .join(", ")
}

pub fn parse_capabilities_header(header_value: &str) -> Vec<Capability> {
    header_value
        .split(',')
        .map(str::trim)
        .filter_map(|value| value.parse().ok())
        .collect()
}

pub fn build_mission_header(mission: &Mission) -> String {
    format!(
        "approver=\"{}\"; s256=\"{}\"",
        mission.approver, mission.s256
    )
}

pub fn parse_mission_header(header_value: &str) -> Result<Mission> {
    let approver = extract_quoted_param(header_value, "approver")
        .ok_or_else(|| AAuthError::InvalidHeader("missing approver".into()))?;
    let s256 = extract_quoted_param(header_value, "s256")
        .ok_or_else(|| AAuthError::InvalidHeader("missing s256".into()))?;
    Ok(Mission { approver, s256 })
}

pub fn build_aauth_requirement(challenge: &AAuthChallenge) -> Result<String> {
    match challenge {
        AAuthChallenge::Approval => Ok("requirement=approval".into()),
        AAuthChallenge::Clarification => Ok("requirement=clarification".into()),
        AAuthChallenge::Claims => Ok("requirement=claims".into()),
        AAuthChallenge::AgentToken => Ok("requirement=agent-token".into()),
        AAuthChallenge::AuthToken { resource_token } => Ok(format!(
            "requirement=auth-token; resource-token=\"{resource_token}\""
        )),
        AAuthChallenge::Interaction { url, code } => Ok(format!(
            "requirement=interaction; url=\"{url}\"; code=\"{code}\""
        )),
    }
}

/// Parse an `AAuth-Requirement` response header value into a structured challenge.
pub fn parse_aauth_requirement(header_value: &str) -> Result<AAuthChallenge> {
    let trimmed = header_value.trim();
    if trimmed.is_empty() {
        return Err(AAuthError::InvalidHeader(
            "empty AAuth-Requirement header".into(),
        ));
    }

    let requirement_match = trimmed
        .strip_prefix("requirement=")
        .and_then(|rest| rest.split(';').next())
        .map(str::trim)
        .ok_or_else(|| {
            AAuthError::InvalidHeader("missing requirement= in AAuth-Requirement header".into())
        })?;

    let level = requirement_match.parse().map_err(|_| {
        AAuthError::InvalidHeader(format!("unknown requirement level: {requirement_match}"))
    })?;

    match level {
        RequirementLevel::AgentToken => Ok(AAuthChallenge::AgentToken),
        RequirementLevel::Approval => Ok(AAuthChallenge::Approval),
        RequirementLevel::Clarification => Ok(AAuthChallenge::Clarification),
        RequirementLevel::Claims => Ok(AAuthChallenge::Claims),
        RequirementLevel::AuthToken => {
            let resource_token = extract_quoted_param(trimmed, "resource-token").ok_or_else(
                || AAuthError::InvalidHeader("auth-token requires resource-token".into()),
            )?;
            Ok(AAuthChallenge::AuthToken { resource_token })
        }
        RequirementLevel::Interaction => {
            let url = extract_quoted_param(trimmed, "url")
                .ok_or_else(|| AAuthError::InvalidHeader("interaction requires url".into()))?;
            let code = extract_quoted_param(trimmed, "code")
                .ok_or_else(|| AAuthError::InvalidHeader("interaction requires code".into()))?;
            Ok(AAuthChallenge::Interaction { url, code })
        }
    }
}

fn extract_quoted_param(input: &str, key: &str) -> Option<String> {
    let pattern = format!(r#"{key}=""#);
    let start = input.find(&pattern)? + pattern.len();
    let rest = &input[start..];
    let end = rest.find('"')?;
    Some(rest[..end].to_string())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn round_trip_auth_token() {
        let challenge = AAuthChallenge::AuthToken {
            resource_token: "rt_abc123".into(),
        };
        let header = build_aauth_requirement(&challenge).unwrap();
        let parsed = parse_aauth_requirement(&header).unwrap();
        assert_eq!(parsed, challenge);
    }

    #[test]
    fn round_trip_interaction() {
        let challenge = AAuthChallenge::Interaction {
            url: "https://auth.example/interact".into(),
            code: "CODE1234".into(),
        };
        let header = build_aauth_requirement(&challenge).unwrap();
        let parsed = parse_aauth_requirement(&header).unwrap();
        assert_eq!(parsed, challenge);
    }

    #[test]
    fn round_trip_approval() {
        let challenge = AAuthChallenge::Approval;
        let header = build_aauth_requirement(&challenge).unwrap();
        let parsed = parse_aauth_requirement(&header).unwrap();
        assert_eq!(parsed, challenge);
    }
}
