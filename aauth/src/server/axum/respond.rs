use axum::Json;
use axum::body::Body;
use axum::http::{HeaderMap, StatusCode};
use axum::response::{IntoResponse, Response};

use crate::server::access::outcome::{AuthTokenFlowOutcome, AuthTokenPollOutcome};
use crate::server::deferred::{
    AcceptedResponse, PendingOutcome, PollResponse, map_snapshot_to_poll_parts,
};
use crate::server::person::outcome::PersonTokenFlowOutcome;
use crate::server::resource::{ResourceConsentFlowOutcome, ResourcePollOutcome};
use crate::types::AAuthProtocolError;

/// Infrastructure failure from a role service. Maps to spec `server_error` (500 + JSON).
#[derive(Debug)]
pub struct InternalServiceError;

impl<E: std::error::Error> From<E> for InternalServiceError {
    fn from(_: E) -> Self {
        Self
    }
}

impl IntoResponse for InternalServiceError {
    fn into_response(self) -> Response {
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(AAuthProtocolError::server_error()),
        )
            .into_response()
    }
}

fn accepted_into_response(accepted: AcceptedResponse) -> Response {
    let mut response = Response::builder().status(accepted.status);
    for (k, v) in accepted.headers.iter() {
        response = response.header(k, v);
    }
    response
        .body(Body::from(accepted.body.to_string()))
        .unwrap_or_else(|_| InternalServiceError.into_response())
}

impl IntoResponse for AuthTokenFlowOutcome {
    fn into_response(self) -> Response {
        match self {
            Self::Granted(body) => (StatusCode::OK, Json(body)).into_response(),
            Self::Deferred(accepted) => accepted_into_response(accepted),
            Self::Denied(err) => (StatusCode::FORBIDDEN, Json(err)).into_response(),
            Self::Gone => StatusCode::GONE.into_response(),
        }
    }
}

impl IntoResponse for AuthTokenPollOutcome {
    fn into_response(self) -> Response {
        match self {
            Self::Pending(accepted) => accepted_into_response(accepted),
            Self::Complete(outcome) => pending_outcome_into_response(outcome),
            Self::Gone => StatusCode::GONE.into_response(),
        }
    }
}

impl IntoResponse for PersonTokenFlowOutcome {
    fn into_response(self) -> Response {
        match self {
            Self::Flow(flow) => flow.into_response(),
            Self::Unauthorized => StatusCode::UNAUTHORIZED.into_response(),
            Self::BadGateway => StatusCode::BAD_GATEWAY.into_response(),
            Self::Gone => StatusCode::GONE.into_response(),
        }
    }
}

impl IntoResponse for ResourceConsentFlowOutcome {
    fn into_response(self) -> Response {
        match self {
            Self::GrantOpaque(token) => {
                let mut headers = HeaderMap::new();
                headers.insert("AAuth-Access", token.parse().expect("valid opaque"));
                (StatusCode::OK, headers).into_response()
            }
            Self::Deferred(accepted) => accepted_into_response(accepted),
            Self::Denied(err) => (StatusCode::FORBIDDEN, Json(err)).into_response(),
        }
    }
}

fn pending_outcome_into_response(outcome: PendingOutcome) -> Response {
    match outcome {
        PendingOutcome::AuthToken(body) => (StatusCode::OK, Json(body)).into_response(),
        PendingOutcome::OpaqueAccess(token) => {
            let mut headers = HeaderMap::new();
            headers.insert("AAuth-Access", token.parse().expect("valid opaque"));
            (StatusCode::OK, headers).into_response()
        }
        PendingOutcome::Error(err) => (err.polling_status(), Json(err)).into_response(),
    }
}

/// Map a pending snapshot to a poll outcome (for service poll methods).
pub fn poll_outcome_from_snapshot(
    snapshot: &crate::server::deferred::PendingSnapshot,
) -> AuthTokenPollOutcome {
    match map_snapshot_to_poll_parts(snapshot) {
        PollResponse::OkAuthToken(body) => {
            AuthTokenPollOutcome::Complete(PendingOutcome::AuthToken(body))
        }
        PollResponse::OkOpaque(token) => {
            AuthTokenPollOutcome::Complete(PendingOutcome::OpaqueAccess(token))
        }
        PollResponse::Error { status: _, error } => {
            AuthTokenPollOutcome::Complete(PendingOutcome::Error(error))
        }
        PollResponse::Gone => AuthTokenPollOutcome::Gone,
        PollResponse::Accepted { headers, body } => {
            let mut accepted_headers = HeaderMap::new();
            for (k, v) in headers.iter() {
                accepted_headers.insert(k.clone(), v.clone());
            }
            AuthTokenPollOutcome::Pending(AcceptedResponse {
                status: StatusCode::ACCEPTED,
                headers: accepted_headers,
                body: body.unwrap_or_else(|| serde_json::json!({ "status": "pending" })),
            })
        }
    }
}

/// Resource poll mapping (same wire shape; removes completed record in handler if needed).
pub fn resource_poll_outcome_from_snapshot(
    snapshot: &crate::server::deferred::PendingSnapshot,
) -> ResourcePollOutcome {
    match poll_outcome_from_snapshot(snapshot) {
        AuthTokenPollOutcome::Pending(a) => ResourcePollOutcome::Pending(a),
        AuthTokenPollOutcome::Complete(o) => ResourcePollOutcome::Complete(o),
        AuthTokenPollOutcome::Gone => ResourcePollOutcome::Gone,
    }
}

/// Build deferred accepted response from location + requirement.
pub fn deferred_accepted(
    location: &str,
    requirement: &crate::server::deferred::DeferRequirement,
) -> Result<AcceptedResponse, crate::error::AAuthError> {
    crate::server::deferred::build_accepted(location, requirement)
}

/// Parse POST body on a pending URL into agent input.
pub fn parse_pending_input(
    body: Option<&serde_json::Value>,
) -> crate::server::deferred::PendingInput {
    use crate::server::deferred::{ClaimsSubmission, PendingInput};
    use crate::types::ClarificationResponse;

    if let Some(value) = body {
        if let Ok(clarification) = serde_json::from_value::<ClarificationResponse>(value.clone()) {
            return PendingInput::ClarificationResponse(clarification.clarification_response);
        }
        if let Ok(claims) = serde_json::from_value::<ClaimsSubmission>(value.clone()) {
            return PendingInput::ClaimsSubmission(claims);
        }
    }
    PendingInput::InteractionCompleted
}
