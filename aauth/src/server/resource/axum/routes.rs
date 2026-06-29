use axum::extract::{Path, State};
use axum::http::{HeaderMap, StatusCode};
use axum::response::{IntoResponse, Response};

use crate::server::deferred::{
    PendingOutcome, PendingSnapshot, PendingStore, PollResponse, map_snapshot_to_poll_parts,
};
use crate::server::resource::opaque::OpaqueAccessStore;

#[derive(Clone)]
pub struct ResourceServerState<S, O>
where
    S: PendingStore,
    O: OpaqueAccessStore + Clone,
{
    pub pending: S,
    pub opaque: O,
}

pub async fn resource_pending_poll_handler<S, O>(
    State(state): State<ResourceServerState<S, O>>,
    Path(id): Path<String>,
) -> Response
where
    S: PendingStore,
    O: OpaqueAccessStore + Clone,
{
    let record = match state.pending.load(&id).await {
        Ok(Some(r)) => r,
        Ok(None) => return StatusCode::GONE.into_response(),
        Err(_) => return StatusCode::INTERNAL_SERVER_ERROR.into_response(),
    };

    if record.is_expired() {
        let _ = state.pending.remove(&id).await;
        return StatusCode::GONE.into_response();
    }

    if let PendingSnapshot::Complete(outcome) = &record.snapshot {
        let _ = state.pending.remove(&id).await;
        return match outcome {
            PendingOutcome::OpaqueAccess(token) => {
                let mut headers = HeaderMap::new();
                headers.insert("AAuth-Access", token.parse().expect("valid opaque"));
                (StatusCode::OK, headers).into_response()
            }
            PendingOutcome::AuthToken(body) => {
                (StatusCode::OK, axum::Json(body.clone())).into_response()
            }
            PendingOutcome::Error(err) => {
                (StatusCode::FORBIDDEN, axum::Json(err.clone())).into_response()
            }
        };
    }

    match map_snapshot_to_poll_parts(&record.snapshot) {
        PollResponse::OkOpaque(token) => {
            let _ = state.pending.remove(&id).await;
            let mut headers = HeaderMap::new();
            headers.insert("AAuth-Access", token.parse().expect("valid opaque"));
            (StatusCode::OK, headers).into_response()
        }
        PollResponse::OkAuthToken(body) => {
            let _ = state.pending.remove(&id).await;
            (StatusCode::OK, axum::Json(body)).into_response()
        }
        PollResponse::Error { status, error } => (status, axum::Json(error)).into_response(),
        PollResponse::Gone => StatusCode::GONE.into_response(),
        PollResponse::Accepted { headers, body } => {
            let mut response = Response::builder().status(StatusCode::ACCEPTED);
            for (k, v) in headers.iter() {
                response = response.header(k, v);
            }
            if let Some(body) = body {
                response
                    .body(axum::body::Body::from(body.to_string()))
                    .unwrap_or_else(|_| StatusCode::INTERNAL_SERVER_ERROR.into_response())
            } else {
                response
                    .body(axum::body::Body::empty())
                    .unwrap_or_else(|_| StatusCode::INTERNAL_SERVER_ERROR.into_response())
            }
        }
    }
}
