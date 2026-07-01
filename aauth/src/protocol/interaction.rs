//! PS `interaction_endpoint` request and response bodies.

use serde::{Deserialize, Serialize};

use super::common::Mission;

/// Interaction request `type` values.
///
/// Spec: `draft-hardt-oauth-aauth-protocol.md#interaction-endpoint`
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum InteractionType {
    Interaction,
    Payment,
    Question,
    Completion,
}

/// Agent POST body to reach the user via the PS.
///
/// Direction: Agent -> PS POST `{interaction_endpoint}`.
///
/// Spec: `draft-hardt-oauth-aauth-protocol.md#interaction-endpoint`
#[serde_with::apply(
    Option => #[serde(default, skip_serializing_if = "Option::is_none")],
)]
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct InteractionRequest {
    #[serde(rename = "type")]
    pub interaction_type: InteractionType,
    pub description: Option<String>,
    pub url: Option<String>,
    pub code: Option<String>,
    pub max_wait: Option<u64>,
    pub question: Option<String>,
    pub summary: Option<String>,
    pub mission: Option<Mission>,
}

/// PS answer to a `question` interaction.
///
/// Direction: PS -> Agent 200 POST `{interaction_endpoint}` (`type=question`).
///
/// Spec: `draft-hardt-oauth-aauth-protocol.md#interaction-response-poll-authority`
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct InteractionQuestionResponse {
    pub answer: String,
}

/// Mission status error when a referenced mission is no longer active.
///
/// Direction: PS -> Agent 403 any governance endpoint with `mission` parameter.
///
/// Spec: `draft-hardt-oauth-aauth-protocol.md#mission-status-errors`
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct MissionStatusError {
    pub error: String,
    pub mission_status: String,
}
