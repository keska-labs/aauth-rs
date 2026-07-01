//! PS `permission_endpoint` request and response bodies.

use serde::{Deserialize, Serialize};
use serde_json::Value;

use super::common::Mission;

/// Agent POST body to request local/tool permission.
///
/// Direction: Agent -> PS POST `{permission_endpoint}`.
///
/// Spec: `draft-hardt-oauth-aauth-protocol.md#permission-endpoint`
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PermissionRequest {
    pub action: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub description: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub parameters: Option<Value>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub mission: Option<Mission>,
}

/// Permission decision returned immediately or after deferred poll.
///
/// Direction: PS -> Agent 200 POST `{permission_endpoint}` or 200 GET `{Location}`.
///
/// Spec: `draft-hardt-oauth-aauth-protocol.md#permission-response`
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PermissionResponse {
    pub permission: PermissionDecision,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub reason: Option<String>,
}

/// `permission` field values.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum PermissionDecision {
    Granted,
    Denied,
}
