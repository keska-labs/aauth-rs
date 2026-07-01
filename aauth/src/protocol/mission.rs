//! PS `mission_endpoint` request and response bodies.

use serde::{Deserialize, Serialize};

use super::common::Capability;

/// Tool entry in a mission proposal or approval blob.
///
/// Spec: `draft-hardt-oauth-aauth-protocol.md#mission-creation`
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct MissionTool {
    pub name: String,
    pub description: String,
}

/// Agent POST body to propose a mission.
///
/// Direction: Agent -> PS POST `{mission_endpoint}`.
///
/// Spec: `draft-hardt-oauth-aauth-protocol.md#mission-creation`
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct MissionProposalRequest {
    pub description: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub tools: Option<Vec<MissionTool>>,
}

/// PS-approved mission blob returned on `200` or pending poll completion.
///
/// Direction: PS -> Agent 200 POST `{mission_endpoint}`; PS -> Agent 200 GET `{Location}`.
///
/// Spec: `draft-hardt-oauth-aauth-protocol.md#mission-approval`
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct MissionBlob {
    pub approver: String,
    pub agent: String,
    pub approved_at: String,
    pub description: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub approved_tools: Option<Vec<MissionTool>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub capabilities: Option<Vec<Capability>>,
}
