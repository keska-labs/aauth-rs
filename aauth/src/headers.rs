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
        .filter_map(Capability::parse)
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

pub fn build_aauth_access(token: &str) -> String {
    token.to_string()
}

#[derive(Debug, Clone, Default)]
pub struct AAuthRequirementParams<'a> {
    pub resource_token: Option<&'a str>,
    pub url: Option<&'a str>,
    pub code: Option<&'a str>,
}

pub fn build_aauth_requirement(
    requirement: RequirementLevel,
    params: Option<&AAuthRequirementParams<'_>>,
) -> Result<String> {
    match requirement {
        RequirementLevel::Approval => Ok("requirement=approval".into()),
        RequirementLevel::Clarification => Ok("requirement=clarification".into()),
        RequirementLevel::Claims => Ok("requirement=claims".into()),
        RequirementLevel::AgentToken => Ok("requirement=agent-token".into()),
        RequirementLevel::AuthToken => {
            let resource_token = params.and_then(|p| p.resource_token).ok_or_else(|| {
                AAuthError::InvalidHeader("auth-token requires resource_token".into())
            })?;
            Ok(format!(
                "requirement=auth-token; resource-token=\"{resource_token}\""
            ))
        }
        RequirementLevel::Interaction => {
            let params = params.ok_or_else(|| {
                AAuthError::InvalidHeader("interaction requires url and code".into())
            })?;
            let url = params
                .url
                .ok_or_else(|| AAuthError::InvalidHeader("interaction requires url".into()))?;
            let code = params
                .code
                .ok_or_else(|| AAuthError::InvalidHeader("interaction requires code".into()))?;
            Ok(format!(
                "requirement=interaction; url=\"{url}\"; code=\"{code}\""
            ))
        }
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

    let requirement = RequirementLevel::parse(requirement_match).ok_or_else(|| {
        AAuthError::InvalidHeader(format!("unknown requirement level: {requirement_match}"))
    })?;

    let challenge = AAuthChallenge {
        requirement,
        resource_token: extract_quoted_param(trimmed, "resource-token"),
        url: extract_quoted_param(trimmed, "url"),
        code: extract_quoted_param(trimmed, "code"),
    };

    Ok(challenge)
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
        let header = build_aauth_requirement(
            RequirementLevel::AuthToken,
            Some(&AAuthRequirementParams {
                resource_token: Some("rt_abc123"),
                ..Default::default()
            }),
        )
        .unwrap();
        let parsed = parse_aauth_requirement(&header).unwrap();
        assert_eq!(parsed.requirement, RequirementLevel::AuthToken);
        assert_eq!(parsed.resource_token.as_deref(), Some("rt_abc123"));
    }

    #[test]
    fn round_trip_interaction() {
        let header = build_aauth_requirement(
            RequirementLevel::Interaction,
            Some(&AAuthRequirementParams {
                url: Some("https://auth.example/interact"),
                code: Some("CODE1234"),
                ..Default::default()
            }),
        )
        .unwrap();
        let parsed = parse_aauth_requirement(&header).unwrap();
        assert_eq!(parsed.requirement, RequirementLevel::Interaction);
        assert_eq!(parsed.url.as_deref(), Some("https://auth.example/interact"));
        assert_eq!(parsed.code.as_deref(), Some("CODE1234"));
    }

    #[test]
    fn round_trip_approval() {
        let header = build_aauth_requirement(RequirementLevel::Approval, None).unwrap();
        let parsed = parse_aauth_requirement(&header).unwrap();
        assert_eq!(parsed.requirement, RequirementLevel::Approval);
    }
}
