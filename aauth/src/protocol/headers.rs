//! AAuth HTTP response/request headers.

use http::HeaderName;

use crate::error::{HeaderError, Result};

use super::common::{Capability, Mission, RequirementLevel};

/// Lowercase name for [`AAUTH_REQUIREMENT`] (also used as a signature covered component).
pub const AAUTH_REQUIREMENT_NAME: &str = "aauth-requirement";
/// `AAuth-Requirement` response header.
pub const AAUTH_REQUIREMENT: HeaderName = HeaderName::from_static(AAUTH_REQUIREMENT_NAME);

/// Lowercase name for [`AAUTH_ACCESS`].
pub const AAUTH_ACCESS_NAME: &str = "aauth-access";
/// `AAuth-Access` response header (opaque resource-managed token).
///
/// Spec: `draft-hardt-oauth-aauth-protocol.md#aauth-access`
pub const AAUTH_ACCESS: HeaderName = HeaderName::from_static(AAUTH_ACCESS_NAME);

/// Lowercase name for [`AAUTH_CAPABILITIES`].
pub const AAUTH_CAPABILITIES_NAME: &str = "aauth-capabilities";
/// `AAuth-Capabilities` request header.
pub const AAUTH_CAPABILITIES: HeaderName = HeaderName::from_static(AAUTH_CAPABILITIES_NAME);

/// Lowercase name for [`AAUTH_MISSION`].
pub const AAUTH_MISSION_NAME: &str = "aauth-mission";
/// `AAuth-Mission` request header.
pub const AAUTH_MISSION: HeaderName = HeaderName::from_static(AAUTH_MISSION_NAME);

/// Lowercase name for [`SIGNATURE_KEY`] (also used as a signature covered component).
pub const SIGNATURE_KEY_NAME: &str = "signature-key";
/// HTTP Message Signatures `Signature-Key` header.
pub const SIGNATURE_KEY: HeaderName = HeaderName::from_static(SIGNATURE_KEY_NAME);

/// Lowercase name for [`SIGNATURE_INPUT`].
pub const SIGNATURE_INPUT_NAME: &str = "signature-input";
/// HTTP Message Signatures `Signature-Input` header.
pub const SIGNATURE_INPUT: HeaderName = HeaderName::from_static(SIGNATURE_INPUT_NAME);

/// Lowercase name for [`SIGNATURE`].
pub const SIGNATURE_NAME: &str = "signature";
/// HTTP Message Signatures `Signature` header.
pub const SIGNATURE: HeaderName = HeaderName::from_static(SIGNATURE_NAME);

/// Lowercase name for [`PREFER`].
pub const PREFER_NAME: &str = "prefer";
/// `Prefer` request header (e.g. `wait=` on token exchange / deferred poll).
pub const PREFER: HeaderName = HeaderName::from_static(PREFER_NAME);

/// Parsed `AAuth-Requirement` response header.
///
/// Direction: Resource -> Agent 401/402 `{AAuth-Requirement}`; PS -> Agent 202 `{AAuth-Requirement}`;
/// AS -> PS 202 `{AAuth-Requirement}` (federation pass-through).
///
/// Spec: `draft-hardt-oauth-aauth-protocol.md#aauth-requirement-header-structure`,
/// `#requirement-responses`
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AAuthChallenge {
    /// `401` — AAuth agent token required.
    ///
    /// Spec: `draft-hardt-oauth-aauth-protocol.md#requirement-agent-token`
    AgentToken,
    /// `401`/`402` — auth token required with embedded resource token.
    ///
    /// Spec: `draft-hardt-oauth-aauth-protocol.md#requirement-auth-token`
    AuthToken { resource_token: String },
    /// `202` — approval pending; poll `Location`.
    ///
    /// Spec: `draft-hardt-oauth-aauth-protocol.md#approval-pending`
    Approval,
    /// `202` — user action required at interaction endpoint.
    ///
    /// Spec: Interaction Required under `#requirement-responses`
    Interaction { url: String, code: String },
    /// `202` — question posed (details in response body).
    ///
    /// Spec: `draft-hardt-oauth-aauth-protocol.md#requirement-clarification`
    Clarification,
    /// `202` — identity claims required (AS only; details in body).
    ///
    /// Spec: `draft-hardt-oauth-aauth-protocol.md#requirement-claims`
    Claims,
}

impl AAuthChallenge {
    pub fn level(&self) -> RequirementLevel {
        match self {
            Self::AgentToken => RequirementLevel::AgentToken,
            Self::AuthToken { .. } => RequirementLevel::AuthToken,
            Self::Approval => RequirementLevel::Approval,
            Self::Interaction { .. } => RequirementLevel::Interaction,
            Self::Clarification => RequirementLevel::Clarification,
            Self::Claims => RequirementLevel::Claims,
        }
    }

    /// Serialize to an `AAuth-Requirement` header value.
    pub fn to_header(&self) -> String {
        match self {
            Self::Approval => "requirement=approval".into(),
            Self::Clarification => "requirement=clarification".into(),
            Self::Claims => "requirement=claims".into(),
            Self::AgentToken => "requirement=agent-token".into(),
            Self::AuthToken { resource_token } => {
                format!("requirement=auth-token; resource-token=\"{resource_token}\"")
            }
            Self::Interaction { url, code } => {
                format!("requirement=interaction; url=\"{url}\"; code=\"{code}\"")
            }
        }
    }

    /// Parse an `AAuth-Requirement` response header value.
    pub fn from_header(header_value: &str) -> Result<Self> {
        let trimmed = header_value.trim();
        if trimmed.is_empty() {
            return Err(HeaderError::EmptyRequirement.into());
        }

        let requirement_match = trimmed
            .strip_prefix("requirement=")
            .and_then(|rest| rest.split(';').next())
            .map(str::trim)
            .ok_or(HeaderError::MissingRequirementMember)?;

        let level = requirement_match
            .parse()
            .map_err(|_| HeaderError::UnknownRequirement(requirement_match.to_string()))?;

        match level {
            RequirementLevel::AgentToken => Ok(Self::AgentToken),
            RequirementLevel::Approval => Ok(Self::Approval),
            RequirementLevel::Clarification => Ok(Self::Clarification),
            RequirementLevel::Claims => Ok(Self::Claims),
            RequirementLevel::AuthToken => {
                let resource_token = extract_quoted_param(trimmed, "resource-token")
                    .ok_or(HeaderError::MissingResourceToken)?;
                Ok(Self::AuthToken { resource_token })
            }
            RequirementLevel::Interaction => {
                let url = extract_quoted_param(trimmed, "url")
                    .ok_or(HeaderError::MissingInteractionUrl)?;
                let code = extract_quoted_param(trimmed, "code")
                    .ok_or(HeaderError::MissingInteractionCode)?;
                Ok(Self::Interaction { url, code })
            }
        }
    }
}

impl Capability {
    /// Join capabilities into an `AAuth-Capabilities` header value.
    pub fn join_header(capabilities: &[Capability]) -> String {
        capabilities
            .iter()
            .map(|c| c.as_str())
            .collect::<Vec<_>>()
            .join(", ")
    }

    /// Parse an `AAuth-Capabilities` header value.
    pub fn parse_header(header_value: &str) -> Vec<Capability> {
        header_value
            .split(',')
            .map(str::trim)
            .filter_map(|value| value.parse().ok())
            .collect()
    }
}

impl Mission {
    /// Serialize to an `AAuth-Mission` header value.
    pub fn to_header(&self) -> String {
        format!("approver=\"{}\"; s256=\"{}\"", self.approver, self.s256)
    }

    /// Parse an `AAuth-Mission` header value.
    pub fn from_header(header_value: &str) -> Result<Self> {
        let approver =
            extract_quoted_param(header_value, "approver").ok_or(HeaderError::MissingApprover)?;
        let s256 = extract_quoted_param(header_value, "s256").ok_or(HeaderError::MissingS256)?;
        Ok(Self { approver, s256 })
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
    fn requirement_round_trip() {
        let challenge = AAuthChallenge::Interaction {
            url: "https://ps.example/interact".into(),
            code: "ABCD-EFGH".into(),
        };
        let header = challenge.to_header();
        assert_eq!(AAuthChallenge::from_header(&header).unwrap(), challenge);
    }
}
