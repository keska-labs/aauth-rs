use axum::body::Bytes;
use axum::extract::FromRequest;
use axum::response::{IntoResponse, Response};
use axum::{Json, http::StatusCode};

use crate::server::deferred::{PendingInput, parse_pending_post_body};
use crate::types::{AAuthErrorCode, AAuthProtocolError};

/// Parsed agent input from POST on a pending URL.
pub struct PendingResumeInput(pub PendingInput);

impl<S> FromRequest<S> for PendingResumeInput
where
    S: Send + Sync,
{
    type Rejection = Response;

    async fn from_request(
        req: axum::http::Request<axum::body::Body>,
        state: &S,
    ) -> Result<Self, Self::Rejection> {
        let (parts, body) = req.into_parts();
        let body = Bytes::from_request(axum::http::Request::from_parts(parts, body), state)
            .await
            .map_err(|_| invalid_request_response("failed to read request body"))?;
        parse_pending_post_body(&body)
            .map(PendingResumeInput)
            .map_err(|e| invalid_request_response(&e.to_string()))
    }
}

fn invalid_request_response(description: &str) -> Response {
    (
        StatusCode::BAD_REQUEST,
        Json(AAuthProtocolError::with_description(
            AAuthErrorCode::InvalidRequest,
            description,
        )),
    )
        .into_response()
}
