use axum::Json;
use axum::http::{HeaderMap, StatusCode};
use axum::response::{IntoResponse, Response};

use crate::deferred::{AuthTokenFlowOutcome, AuthTokenPollOutcome};
use crate::deferred::{
    DeferCreated, DeferWaiting, PaymentRequiredDefer, PendingOutcome, PendingSnapshot,
};
#[cfg(feature = "person-server-axum")]
use crate::person_server::outcome::PersonTokenFlowOutcome;
use crate::protocol::build_aauth_requirement;
use crate::protocol::{AAuthErrorCode, AAuthProtocolError, PaymentRequiredBody, PendingBody};
#[cfg(feature = "resource-axum")]
use crate::resource::{ResourceConsentFlowOutcome, ResourcePollOutcome};

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

/// HTTP status for a polling error response.
///
/// Spec: https://github.com/dickhardt/AAuth/blob/main/draft-hardt-oauth-aauth-protocol.md#polling-error-codes
pub fn polling_status(err: &AAuthProtocolError) -> StatusCode {
    match err.error {
        AAuthErrorCode::Denied | AAuthErrorCode::Abandoned | AAuthErrorCode::AccessDenied => {
            StatusCode::FORBIDDEN
        }
        AAuthErrorCode::Expired | AAuthErrorCode::InteractionExpired => StatusCode::REQUEST_TIMEOUT,
        AAuthErrorCode::InvalidCode => StatusCode::GONE,
        AAuthErrorCode::SlowDown => StatusCode::TOO_MANY_REQUESTS,
        AAuthErrorCode::ServerError | AAuthErrorCode::TemporarilyUnavailable => {
            StatusCode::INTERNAL_SERVER_ERROR
        }
        AAuthErrorCode::Custom(ref code) => match code.as_str() {
            "denied" | "abandoned" | "access_denied" => StatusCode::FORBIDDEN,
            "expired" | "interaction_expired" => StatusCode::REQUEST_TIMEOUT,
            "invalid_code" => StatusCode::GONE,
            "slow_down" => StatusCode::TOO_MANY_REQUESTS,
            "server_error" | "temporarily_unavailable" => StatusCode::INTERNAL_SERVER_ERROR,
            _ => StatusCode::FORBIDDEN,
        },
        _ => StatusCode::FORBIDDEN,
    }
}

fn insert_poll_headers(headers: &mut HeaderMap, requirement: &crate::deferred::DeferRequirement) {
    headers.insert("Retry-After", "0".parse().expect("valid header"));
    headers.insert("Cache-Control", "no-store".parse().expect("valid header"));
    if let Ok(challenge) = requirement.header_challenge() {
        if let Ok(req) = build_aauth_requirement(&challenge) {
            headers.insert(
                "AAuth-Requirement",
                req.parse().expect("valid requirement header"),
            );
        }
    }
}

fn insert_defer_created_headers(
    headers: &mut HeaderMap,
    location: &str,
    requirement: &crate::deferred::DeferRequirement,
) {
    headers.insert("Location", location.parse().expect("valid location"));
    insert_poll_headers(headers, requirement);
    headers.insert(
        "Content-Type",
        "application/json".parse().expect("valid content-type"),
    );
}

impl IntoResponse for DeferCreated {
    fn into_response(self) -> Response {
        let body = match PendingBody::for_created(&self.requirement) {
            Ok(b) => b,
            Err(e) => return (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()).into_response(),
        };
        let mut headers = HeaderMap::new();
        insert_defer_created_headers(&mut headers, &self.location, &self.requirement);
        (StatusCode::ACCEPTED, headers, Json(body)).into_response()
    }
}

impl IntoResponse for DeferWaiting {
    fn into_response(self) -> Response {
        let body = match PendingBody::for_waiting(&self.requirement, self.status) {
            Ok(b) => b,
            Err(e) => return (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()).into_response(),
        };
        let mut headers = HeaderMap::new();
        insert_poll_headers(&mut headers, &self.requirement);
        headers.insert(
            "Content-Type",
            "application/json".parse().expect("valid content-type"),
        );
        (StatusCode::ACCEPTED, headers, Json(body)).into_response()
    }
}

impl IntoResponse for PaymentRequiredDefer {
    fn into_response(self) -> Response {
        let mut headers = HeaderMap::new();
        headers.insert("Location", self.location.parse().expect("valid location"));
        headers.insert(
            "Content-Type",
            "application/json".parse().expect("valid content-type"),
        );
        (
            StatusCode::PAYMENT_REQUIRED,
            headers,
            Json(PaymentRequiredBody::pending()),
        )
            .into_response()
    }
}

#[cfg(any(feature = "access-server-axum", feature = "person-server-axum"))]
impl IntoResponse for AuthTokenFlowOutcome {
    fn into_response(self) -> Response {
        match self {
            Self::Granted(body) => (StatusCode::OK, Json(body)).into_response(),
            Self::Deferred(defer) => defer.into_response(),
            Self::Denied(err) => (StatusCode::FORBIDDEN, Json(err)).into_response(),
            Self::Gone => StatusCode::GONE.into_response(),
        }
    }
}

#[cfg(any(
    feature = "access-server-axum",
    feature = "person-server-axum",
    feature = "resource-axum"
))]
impl IntoResponse for AuthTokenPollOutcome {
    fn into_response(self) -> Response {
        match self {
            Self::Pending(waiting) => waiting.into_response(),
            Self::Complete(outcome) => outcome.into_response(),
            Self::Gone => StatusCode::GONE.into_response(),
        }
    }
}

#[cfg(feature = "person-server-axum")]
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

#[cfg(feature = "resource-axum")]
impl IntoResponse for ResourceConsentFlowOutcome {
    fn into_response(self) -> Response {
        match self {
            Self::GrantOpaque(token) => {
                let mut headers = HeaderMap::new();
                headers.insert("AAuth-Access", token.parse().expect("valid opaque"));
                (StatusCode::OK, headers).into_response()
            }
            Self::Deferred(defer) => defer.into_response(),
            Self::Denied(err) => (StatusCode::FORBIDDEN, Json(err)).into_response(),
        }
    }
}

impl IntoResponse for PendingOutcome {
    fn into_response(self) -> Response {
        match self {
            Self::AuthToken(body) => (StatusCode::OK, Json(body)).into_response(),
            Self::OpaqueAccess(token) => {
                let mut headers = HeaderMap::new();
                headers.insert("AAuth-Access", token.parse().expect("valid opaque"));
                (StatusCode::OK, headers).into_response()
            }
            Self::Error(err) => (polling_status(&err), Json(err)).into_response(),
        }
    }
}

/// Map a pending snapshot to a poll outcome (for service poll methods).
#[cfg(any(
    feature = "access-server-axum",
    feature = "person-server-axum",
    feature = "resource-axum"
))]
pub fn poll_outcome_from_snapshot(snapshot: &PendingSnapshot) -> AuthTokenPollOutcome {
    match snapshot {
        PendingSnapshot::Complete(outcome) => AuthTokenPollOutcome::Complete(outcome.clone()),
        PendingSnapshot::Waiting {
            status,
            requirement,
        } => AuthTokenPollOutcome::Pending(DeferWaiting {
            status: *status,
            requirement: requirement.clone(),
        }),
    }
}

/// Resource poll mapping (same wire shape; removes completed record in handler if needed).
#[cfg(feature = "resource-axum")]
pub fn resource_poll_outcome_from_snapshot(snapshot: &PendingSnapshot) -> ResourcePollOutcome {
    poll_outcome_from_snapshot(snapshot)
}
