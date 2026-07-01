//! Shared protocol enums and value types referenced by multiple wire sections.

use std::str::FromStr;

use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ParseStrError;

/// `AAuth-Requirement` `requirement` member values.
///
/// Spec: `draft-hardt-oauth-aauth-protocol.md#requirement-values`
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum RequirementLevel {
    /// `401` — AAuth agent token required for identity-only access.
    AgentToken,
    /// `401` — auth token required; carries a `resource-token` parameter.
    AuthToken,
    /// `202` — approval pending; poll `Location` for result.
    Approval,
    /// `202` — user action required at an interaction endpoint.
    Interaction,
    /// `202` — question posed to the recipient.
    Clarification,
    /// `202` — identity claims required (AS only).
    Claims,
}

impl RequirementLevel {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::AgentToken => "agent-token",
            Self::AuthToken => "auth-token",
            Self::Approval => "approval",
            Self::Interaction => "interaction",
            Self::Clarification => "clarification",
            Self::Claims => "claims",
        }
    }
}

impl std::fmt::Display for RequirementLevel {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.as_str())
    }
}

impl FromStr for RequirementLevel {
    type Err = ParseStrError;

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        match value {
            "agent-token" => Ok(Self::AgentToken),
            "auth-token" => Ok(Self::AuthToken),
            "approval" => Ok(Self::Approval),
            "interaction" => Ok(Self::Interaction),
            "clarification" => Ok(Self::Clarification),
            "claims" => Ok(Self::Claims),
            _ => Err(ParseStrError),
        }
    }
}

/// `AAuth-Capabilities` header and token-request capability values.
///
/// Spec: `draft-hardt-oauth-aauth-protocol.md#aauth-capabilities-request-header-aauth-capabilities`
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum Capability {
    /// Agent can get a user to an interaction URL, directly or via its PS.
    Interaction,
    /// Agent can engage in clarification chat.
    Clarification,
    /// Agent can handle `402` payment flows.
    Payment,
}

impl Capability {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Interaction => "interaction",
            Self::Clarification => "clarification",
            Self::Payment => "payment",
        }
    }
}

impl std::fmt::Display for Capability {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.as_str())
    }
}

impl FromStr for Capability {
    type Err = ParseStrError;

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        match value {
            "interaction" => Ok(Self::Interaction),
            "clarification" => Ok(Self::Clarification),
            "payment" => Ok(Self::Payment),
            _ => Err(ParseStrError),
        }
    }
}

/// `202` pending response body `status` values.
///
/// Spec: `draft-hardt-oauth-aauth-protocol.md#pending-response`
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum PendingStatus {
    /// Request is waiting for completion.
    Pending,
    /// User has arrived at the interaction endpoint.
    Interacting,
}

/// Mission reference (`approver`, `s256`) in headers and JWT claims.
///
/// Direction: Agent -> PS POST `{mission_endpoint}` request header; PS -> Agent 200 mission blob;
/// Agent -> Resource any signed request header; Resource -> PS/AS embedded in resource/auth tokens.
///
/// Spec: `draft-hardt-oauth-aauth-protocol.md#aauth-mission-request-header`
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Mission {
    /// HTTPS URL of the entity that approved the mission. Compared by exact string match.
    pub approver: String,
    /// Unpadded base64url SHA-256 digest of the approved mission JSON bytes.
    pub s256: String,
}
