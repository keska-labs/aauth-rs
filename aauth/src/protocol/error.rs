//! Protocol error response bodies and error codes.

use std::str::FromStr;

use serde::{Deserialize, Serialize};

/// Spec-defined AAuth protocol error codes.
///
/// Direction: PS/Resource/AS -> Agent|PS error response bodies (4xx/5xx JSON).
///
/// Spec: `draft-hardt-oauth-aauth-protocol.md#error-response-format`
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AAuthErrorCode {
    InvalidRequest,
    InvalidAgentToken,
    ExpiredAgentToken,
    InvalidResourceToken,
    ExpiredResourceToken,
    UserUnreachable,
    ServerError,
    InvalidSignature,
    InvalidScope,
    Denied,
    Abandoned,
    Expired,
    InvalidCode,
    SlowDown,
    InvalidInput,
    InvalidKey,
    UnknownKey,
    InvalidJwt,
    ExpiredJwt,
    AccessDenied,
    UserAbandoned,
    InteractionExpired,
    TemporarilyUnavailable,
    InteractionUnavailable,
    MissionTerminated,
    Custom(String),
}

impl AAuthErrorCode {
    pub fn as_str(&self) -> &str {
        match self {
            Self::InvalidRequest => "invalid_request",
            Self::InvalidAgentToken => "invalid_agent_token",
            Self::ExpiredAgentToken => "expired_agent_token",
            Self::InvalidResourceToken => "invalid_resource_token",
            Self::ExpiredResourceToken => "expired_resource_token",
            Self::UserUnreachable => "user_unreachable",
            Self::ServerError => "server_error",
            Self::InvalidSignature => "invalid_signature",
            Self::InvalidScope => "invalid_scope",
            Self::Denied => "denied",
            Self::Abandoned => "abandoned",
            Self::Expired => "expired",
            Self::InvalidCode => "invalid_code",
            Self::SlowDown => "slow_down",
            Self::InvalidInput => "invalid_input",
            Self::InvalidKey => "invalid_key",
            Self::UnknownKey => "unknown_key",
            Self::InvalidJwt => "invalid_jwt",
            Self::ExpiredJwt => "expired_jwt",
            Self::AccessDenied => "access_denied",
            Self::UserAbandoned => "user_abandoned",
            Self::InteractionExpired => "interaction_expired",
            Self::TemporarilyUnavailable => "temporarily_unavailable",
            Self::InteractionUnavailable => "interaction_unavailable",
            Self::MissionTerminated => "mission_terminated",
            Self::Custom(code) => code,
        }
    }

    pub fn from_wire(s: &str) -> Self {
        match s {
            "invalid_request" => Self::InvalidRequest,
            "invalid_agent_token" => Self::InvalidAgentToken,
            "expired_agent_token" => Self::ExpiredAgentToken,
            "invalid_resource_token" => Self::InvalidResourceToken,
            "expired_resource_token" => Self::ExpiredResourceToken,
            "user_unreachable" => Self::UserUnreachable,
            "server_error" => Self::ServerError,
            "invalid_signature" => Self::InvalidSignature,
            "invalid_scope" => Self::InvalidScope,
            "denied" => Self::Denied,
            "abandoned" => Self::Abandoned,
            "expired" => Self::Expired,
            "invalid_code" => Self::InvalidCode,
            "slow_down" => Self::SlowDown,
            "invalid_input" => Self::InvalidInput,
            "invalid_key" => Self::InvalidKey,
            "unknown_key" => Self::UnknownKey,
            "invalid_jwt" => Self::InvalidJwt,
            "expired_jwt" => Self::ExpiredJwt,
            "access_denied" => Self::AccessDenied,
            "user_abandoned" => Self::UserAbandoned,
            "interaction_expired" => Self::InteractionExpired,
            "temporarily_unavailable" => Self::TemporarilyUnavailable,
            "interaction_unavailable" => Self::InteractionUnavailable,
            "mission_terminated" => Self::MissionTerminated,
            other => Self::Custom(other.to_string()),
        }
    }
}

impl std::fmt::Display for AAuthErrorCode {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.as_str())
    }
}

impl Serialize for AAuthErrorCode {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        serializer.serialize_str(self.as_str())
    }
}

impl<'de> Deserialize<'de> for AAuthErrorCode {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        let s = String::deserialize(deserializer)?;
        Ok(Self::from_wire(&s))
    }
}

impl FromStr for AAuthErrorCode {
    type Err = std::convert::Infallible;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Ok(Self::from_wire(s))
    }
}

/// Token endpoint, polling, or authorization error response body.
///
/// Direction: PS/Resource/AS -> Agent|PS 4xx/5xx JSON error bodies.
///
/// Spec: `draft-hardt-oauth-aauth-protocol.md#error-response-format`
#[serde_with::apply(
    Option => #[serde(default, skip_serializing_if = "Option::is_none")],
)]
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AAuthProtocolError {
    pub error: AAuthErrorCode,
    pub error_description: Option<String>,
    pub error_uri: Option<String>,
}

impl AAuthProtocolError {
    pub fn new(code: AAuthErrorCode) -> Self {
        Self {
            error: code,
            error_description: None,
            error_uri: None,
        }
    }

    pub fn with_description(code: AAuthErrorCode, description: impl Into<String>) -> Self {
        Self {
            error: code,
            error_description: Some(description.into()),
            error_uri: None,
        }
    }

    pub fn server_error() -> Self {
        Self::new(AAuthErrorCode::ServerError)
    }
}
