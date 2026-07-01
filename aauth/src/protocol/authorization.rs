//! Resource `authorization_endpoint` request and response bodies.

use serde::{Deserialize, Serialize};

/// Agent POST body to the resource `authorization_endpoint`.
///
/// Direction: Agent -> Resource POST `{authorization_endpoint}`.
///
/// Spec: `draft-hardt-oauth-aauth-protocol.md#authorization-endpoint-request`
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AuthorizationRequest {
    /// Space-separated scope values the agent is requesting.
    pub scope: String,
}

/// Resource token issued by the authorization endpoint or embedded in `401` challenge.
///
/// Direction: Resource -> Agent 200 POST `{authorization_endpoint}`.
///
/// Spec: `draft-hardt-oauth-aauth-protocol.md#authorization-endpoint-responses`
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ResourceTokenResponse {
    pub resource_token: String,
}

/// Immediate authorization grant without a resource token (resource-managed / identity binding).
///
/// Direction: Resource -> Agent 200 POST `{authorization_endpoint}` or 200 pending poll.
///
/// Spec: `draft-hardt-oauth-aauth-protocol.md#authorization-endpoint-responses`
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AuthorizationGrantedResponse {
    pub status: String,
    pub scope: String,
}

/// Identity-based access success response (optional illustrative body).
///
/// Direction: Resource -> Agent 200 any protected API path.
///
/// Spec: `draft-hardt-oauth-aauth-protocol.md#overview-identity-access`
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AgentOkResponse {
    pub status: String,
    pub agent: String,
}

/// Auth-token access success response (optional illustrative body).
///
/// Direction: Resource -> Agent 200 any protected API path.
#[serde_with::apply(
    Option => #[serde(default, skip_serializing_if = "Option::is_none")],
)]
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuthOkResponse {
    pub status: String,
    pub user: Option<String>,
}
