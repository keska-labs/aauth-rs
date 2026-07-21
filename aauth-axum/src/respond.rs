use axum::Json;
use axum::http::{HeaderMap, StatusCode};
use axum::response::{IntoResponse, Response};

use aauth::deferred::{AuthTokenFlowOutcome, AuthTokenPollOutcome};
use aauth::deferred::{DeferCreated, DeferWaiting, PaymentRequiredDefer, PendingOutcome};
#[cfg(feature = "person-server")]
use aauth::person_server::outcome::{PersonInteractionOutcome, PersonTokenFlowOutcome};
use aauth::protocol::{AAuthErrorCode, AAuthProtocolError, PaymentRequiredBody, PendingBody};
#[cfg(feature = "resource")]
use aauth::resource::ResourceConsentFlowOutcome;

/// Owned wrapper so this crate can implement [`IntoResponse`] for `aauth` domain types
/// (orphan rule).
#[derive(Debug, Clone)]
pub struct AauthResponse<T>(pub T);

impl<T> From<T> for AauthResponse<T> {
    fn from(value: T) -> Self {
        Self(value)
    }
}

/// Infrastructure failure from a role service. Maps to spec `server_error` (500 + JSON).
#[derive(Debug)]
pub struct InternalServiceError;

impl<E: std::error::Error> From<E> for InternalServiceError {
    fn from(e: E) -> Self {
        // Keep typed source visible for operators; wire body stays opaque `server_error`.
        eprintln!("aauth internal service error: {e:#}");
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

fn insert_poll_headers(headers: &mut HeaderMap, requirement: &aauth::deferred::DeferRequirement) {
    headers.insert("Retry-After", "0".parse().expect("valid header"));
    headers.insert("Cache-Control", "no-store".parse().expect("valid header"));
    if let Ok(challenge) = requirement.header_challenge() {
        headers.insert(
            "AAuth-Requirement",
            challenge
                .to_header()
                .parse()
                .expect("valid requirement header"),
        );
    }
}

fn insert_defer_created_headers(
    headers: &mut HeaderMap,
    location: &str,
    requirement: &aauth::deferred::DeferRequirement,
) {
    headers.insert("Location", location.parse().expect("valid location"));
    insert_poll_headers(headers, requirement);
    headers.insert(
        "Content-Type",
        "application/json".parse().expect("valid content-type"),
    );
}

impl IntoResponse for AauthResponse<DeferCreated> {
    fn into_response(self) -> Response {
        let body = match PendingBody::for_created(&self.0.requirement) {
            Ok(b) => b,
            Err(_) => return InternalServiceError.into_response(),
        };
        let mut headers = HeaderMap::new();
        insert_defer_created_headers(&mut headers, &self.0.location, &self.0.requirement);
        (StatusCode::ACCEPTED, headers, Json(body)).into_response()
    }
}

impl IntoResponse for AauthResponse<DeferWaiting> {
    fn into_response(self) -> Response {
        let body = match PendingBody::for_waiting(&self.0.requirement, self.0.status) {
            Ok(b) => b,
            Err(_) => return InternalServiceError.into_response(),
        };
        let mut headers = HeaderMap::new();
        insert_poll_headers(&mut headers, &self.0.requirement);
        headers.insert(
            "Content-Type",
            "application/json".parse().expect("valid content-type"),
        );
        (StatusCode::ACCEPTED, headers, Json(body)).into_response()
    }
}

impl IntoResponse for AauthResponse<PaymentRequiredDefer> {
    fn into_response(self) -> Response {
        let mut headers = HeaderMap::new();
        headers.insert("Location", self.0.location.parse().expect("valid location"));
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

impl IntoResponse for AauthResponse<AuthTokenFlowOutcome> {
    fn into_response(self) -> Response {
        match self.0 {
            AuthTokenFlowOutcome::Granted(body) => (StatusCode::OK, Json(body)).into_response(),
            AuthTokenFlowOutcome::Deferred(defer) => AauthResponse(defer).into_response(),
            AuthTokenFlowOutcome::Denied(err) => (StatusCode::FORBIDDEN, Json(err)).into_response(),
            AuthTokenFlowOutcome::Gone => StatusCode::GONE.into_response(),
        }
    }
}

impl IntoResponse for AauthResponse<AuthTokenPollOutcome> {
    fn into_response(self) -> Response {
        match self.0 {
            AuthTokenPollOutcome::Pending(waiting) => AauthResponse(waiting).into_response(),
            AuthTokenPollOutcome::Complete(outcome) => AauthResponse(outcome).into_response(),
            AuthTokenPollOutcome::Gone => StatusCode::GONE.into_response(),
        }
    }
}

#[cfg(feature = "person-server")]
impl IntoResponse for AauthResponse<PersonTokenFlowOutcome> {
    fn into_response(self) -> Response {
        match self.0 {
            PersonTokenFlowOutcome::Granted(body) => {
                AauthResponse(AuthTokenFlowOutcome::Granted(body)).into_response()
            }
            PersonTokenFlowOutcome::Deferred(defer) => {
                AauthResponse(AuthTokenFlowOutcome::Deferred(defer)).into_response()
            }
            PersonTokenFlowOutcome::Denied(err) => {
                AauthResponse(AuthTokenFlowOutcome::Denied(err)).into_response()
            }
            PersonTokenFlowOutcome::Gone => StatusCode::GONE.into_response(),
            PersonTokenFlowOutcome::Unauthorized => StatusCode::UNAUTHORIZED.into_response(),
            PersonTokenFlowOutcome::BadGateway => StatusCode::BAD_GATEWAY.into_response(),
        }
    }
}

#[cfg(feature = "person-server")]
impl IntoResponse for AauthResponse<PersonInteractionOutcome> {
    fn into_response(self) -> Response {
        match self.0 {
            PersonInteractionOutcome::Redirect(location) => {
                (StatusCode::FOUND, [(http::header::LOCATION, location)]).into_response()
            }
            PersonInteractionOutcome::InvalidCode => (
                StatusCode::GONE,
                Json(AAuthProtocolError::new(AAuthErrorCode::InvalidCode)),
            )
                .into_response(),
            PersonInteractionOutcome::Expired => (
                polling_status(&AAuthProtocolError::new(AAuthErrorCode::Expired)),
                Json(AAuthProtocolError::new(AAuthErrorCode::Expired)),
            )
                .into_response(),
            PersonInteractionOutcome::Pending(body) => (StatusCode::OK, Json(body)).into_response(),
        }
    }
}

#[cfg(feature = "resource")]
impl IntoResponse for AauthResponse<ResourceConsentFlowOutcome> {
    fn into_response(self) -> Response {
        match self.0 {
            ResourceConsentFlowOutcome::GrantOpaque(token) => {
                let mut headers = HeaderMap::new();
                headers.insert("AAuth-Access", token.parse().expect("valid opaque"));
                (StatusCode::OK, headers).into_response()
            }
            ResourceConsentFlowOutcome::Deferred(defer) => AauthResponse(defer).into_response(),
            ResourceConsentFlowOutcome::Denied(err) => {
                (StatusCode::FORBIDDEN, Json(err)).into_response()
            }
        }
    }
}

impl IntoResponse for AauthResponse<PendingOutcome> {
    fn into_response(self) -> Response {
        match self.0 {
            PendingOutcome::AuthToken(body) => (StatusCode::OK, Json(body)).into_response(),
            PendingOutcome::OpaqueAccess(token) => {
                let mut headers = HeaderMap::new();
                headers.insert("AAuth-Access", token.parse().expect("valid opaque"));
                (StatusCode::OK, headers).into_response()
            }
            PendingOutcome::Error(err) => (polling_status(&err), Json(err)).into_response(),
        }
    }
}
