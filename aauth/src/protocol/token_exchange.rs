//! Token endpoint request and response bodies.

use serde::{Deserialize, Serialize};

use super::common::Capability;

/// Agent POST body to the PS `token_endpoint`.
///
/// Direction: Agent -> PS POST `{token_endpoint}`; Resource -> PS POST `{token_endpoint}` (call chaining).
///
/// Spec: `draft-hardt-oauth-aauth-protocol.md#agent-token-request`
#[serde_with::apply(
    Option => #[serde(default, skip_serializing_if = "Option::is_none")],
)]
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TokenExchangeRequest {
    pub resource_token: String,
    /// Spec: `#call-chaining`, `#upstream-token-verification` (runtime not yet wired).
    pub upstream_token: Option<String>,
    /// Spec: `#sub-agents` (parent-mediated; runtime not yet wired).
    pub subagent_token: Option<String>,
    pub justification: Option<String>,
    pub login_hint: Option<String>,
    pub tenant: Option<String>,
    pub domain_hint: Option<String>,
    pub capabilities: Option<Vec<Capability>>,
    pub prompt: Option<String>,
    pub platform: Option<String>,
    pub device: Option<String>,
}

/// PS-to-AS (or resource-as-agent-to-AS) token exchange request body.
///
/// Direction: PS -> AS POST `{token_endpoint}`; Resource -> AS POST `{token_endpoint}` (call chaining).
///
/// Spec: `draft-hardt-oauth-aauth-protocol.md#ps-to-as-token-request`
#[serde_with::apply(
    Option => #[serde(default, skip_serializing_if = "Option::is_none")],
)]
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AccessTokenExchangeRequest {
    pub resource_token: String,
    pub agent_token: String,
    /// Spec: `#call-chaining`, `#upstream-token-verification` (runtime not yet wired).
    pub upstream_token: Option<String>,
    /// Spec: `#sub-agents` (runtime not yet wired).
    pub subagent_token: Option<String>,
}

/// Direct grant (`200`) token endpoint response body.
///
/// Direction: PS -> Agent 200 POST `{token_endpoint}`; AS -> PS 200 POST `{token_endpoint}`.
///
/// Spec: `draft-hardt-oauth-aauth-protocol.md#ps-response`
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TokenResponseBody {
    pub auth_token: String,
    pub expires_in: u64,
}
