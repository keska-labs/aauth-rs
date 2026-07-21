//! Deferred (`202`/`402`) and pending URL wire bodies.

use serde::{Deserialize, Serialize};

use super::common::PendingStatus;

fn default_pending_status() -> PendingStatus {
    PendingStatus::Pending
}

/// Status-only pending response body (`interaction` / `approval` deferrals).
///
/// Direction: Resource -> Agent 202 `{Location}`; PS -> Agent 202 `{Location}`; AS -> PS 202 `{Location}`.
///
/// Spec: `draft-hardt-oauth-aauth-protocol.md#pending-response`
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct PendingStatusBody {
    pub status: PendingStatus,
}

/// `202` pending response body for `requirement=clarification`.
///
/// Direction: PS -> Agent 202 GET/POST `{Location}`; Resource -> Agent 202 `{Location}`; AS -> PS 202 `{Location}`.
///
/// Spec: `draft-hardt-oauth-aauth-protocol.md#requirement-clarification`
#[serde_with::apply(
    Option => #[serde(default, skip_serializing_if = "Option::is_none")],
)]
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ClarificationChallenge {
    #[serde(default = "default_pending_status")]
    pub status: PendingStatus,
    pub clarification: String,
    pub timeout: Option<u64>,
    pub options: Option<Vec<String>>,
}

/// `202` pending response body for `requirement=claims`.
///
/// Direction: AS -> PS 202 GET `{Location}` (federation).
///
/// Spec: `draft-hardt-oauth-aauth-protocol.md#requirement-claims`
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ClaimsChallenge {
    pub status: PendingStatus,
    pub required_claims: Vec<String>,
}

/// JSON body on a `202` pending / defer response.
///
/// Direction: PS/Resource/AS -> Agent|PS 202 `{Location}` response body.
///
/// Spec: `draft-hardt-oauth-aauth-protocol.md#deferred-responses`
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(untagged)]
pub enum PendingBody {
    Status(PendingStatusBody),
    Clarification(ClarificationChallenge),
    Claims(ClaimsChallenge),
}

/// Agent POST body to answer a clarification on a pending URL.
///
/// Direction: Agent -> PS POST `{Location}`; Agent -> Resource POST `{Location}`; PS -> AS POST `{Location}`.
///
/// Spec: `draft-hardt-oauth-aauth-protocol.md#clarification-response`
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ClarificationResponse {
    pub clarification_response: String,
}

/// Identity claims POSTed to a pending URL for `requirement=claims`.
///
/// Direction: PS -> AS POST `{Location}`; Agent -> PS POST `{Location}` (pass-through).
///
/// Spec: `draft-hardt-oauth-aauth-protocol.md#requirement-claims`
#[serde_with::apply(
    Option => #[serde(default, skip_serializing_if = "Option::is_none")],
)]
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ClaimsSubmission {
    pub sub: String,
    pub email: Option<String>,
    pub tenant: Option<String>,
    #[serde(flatten)]
    pub extra: std::collections::HashMap<String, serde_json::Value>,
}

/// Agent POST body with an updated resource token during consent deferral.
///
/// Direction: Agent -> PS POST `{Location}`; Agent -> Resource POST `{Location}`; PS -> AS POST `{Location}`.
///
/// Spec: `draft-hardt-oauth-aauth-protocol.md#updated-request`
#[serde_with::apply(
    Option => #[serde(default, skip_serializing_if = "Option::is_none")],
)]
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct UpdatedTokenRequest {
    pub resource_token: String,
    pub justification: Option<String>,
}

/// Empty `{}` or omitted body = interaction completed on a pending URL.
///
/// Direction: Agent -> PS POST `{Location}`; Agent -> Resource POST `{Location}`.
#[derive(Debug, Clone, Deserialize)]
pub struct InteractionCompletedBody {}

/// Agent POST body on a pending URL (no wire discriminator in spec yet).
///
/// Direction: Agent -> PS/Resource/AS POST `{Location}`.
///
/// Spec: `draft-hardt-oauth-aauth-protocol.md#agent-response-to-clarification`
#[derive(Debug, Clone, Deserialize)]
#[serde(untagged)]
pub enum PendingPostBody {
    Clarification(ClarificationResponse),
    Claims(ClaimsSubmission),
    UpdatedToken(UpdatedTokenRequest),
    InteractionCompleted(InteractionCompletedBody),
}

/// `402 Payment Required` deferred poll body (minimal stub).
///
/// Direction: AS -> PS 402 POST `{token_endpoint}`; Resource -> Agent 402 API response.
///
/// Spec: `draft-hardt-oauth-aauth-protocol.md#requirement-responses`
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PaymentRequiredBody {
    pub status: String,
}

impl PaymentRequiredBody {
    pub fn pending() -> Self {
        Self {
            status: "pending".into(),
        }
    }
}
