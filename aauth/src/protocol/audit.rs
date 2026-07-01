//! PS `audit_endpoint` request body.

use serde::{Deserialize, Serialize};
use serde_json::Value;

use super::common::Mission;

/// Agent POST body to log a mission action.
///
/// Direction: Agent -> PS POST `{audit_endpoint}`.
///
/// Spec: `draft-hardt-oauth-aauth-protocol.md#audit-endpoint`
#[serde_with::apply(
    Option => #[serde(default, skip_serializing_if = "Option::is_none")],
)]
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AuditRequest {
    pub mission: Mission,
    pub action: String,
    pub description: Option<String>,
    pub parameters: Option<Value>,
    pub result: Option<Value>,
}
