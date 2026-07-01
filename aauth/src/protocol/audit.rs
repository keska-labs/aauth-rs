//! PS `audit_endpoint` request body.

use serde::{Deserialize, Serialize};
use serde_json::Value;

use super::common::Mission;

/// Agent POST body to log a mission action.
///
/// Direction: Agent -> PS POST `{audit_endpoint}`.
///
/// Spec: `draft-hardt-oauth-aauth-protocol.md#audit-endpoint`
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AuditRequest {
    pub mission: Mission,
    pub action: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub description: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub parameters: Option<Value>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub result: Option<Value>,
}
