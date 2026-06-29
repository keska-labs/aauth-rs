use axum::extract::{Path, State};
use axum::http::{HeaderMap, StatusCode};
use axum::response::{IntoResponse, Response};

use crate::server::interaction::InteractionManager;

#[derive(Clone)]
pub struct ResourceServerState {
    pub interaction_manager: std::sync::Arc<InteractionManager>,
}

pub async fn resource_pending_poll_handler(
    State(state): State<ResourceServerState>,
    Path(id): Path<String>,
) -> Response {
    let manager = &state.interaction_manager;
    let Some(pending) = manager.get_pending(id.as_str()) else {
        return StatusCode::GONE.into_response();
    };

    if let Some(opaque) = pending.opaque_access.lock().unwrap().clone() {
        manager.remove(&id);
        let mut headers = HeaderMap::new();
        headers.insert("AAuth-Access", opaque.parse().expect("valid opaque token"));
        return (StatusCode::OK, headers).into_response();
    }

    if let Some(result) = pending.result.lock().unwrap().clone() {
        match result {
            Ok(_) => {
                manager.remove(&id);
                return StatusCode::OK.into_response();
            }
            Err(err) => {
                manager.remove(&id);
                return (StatusCode::INTERNAL_SERVER_ERROR, err).into_response();
            }
        }
    }

    let mut headers = HeaderMap::new();
    headers.insert("Retry-After", "0".parse().expect("valid header"));
    headers.insert("Cache-Control", "no-store".parse().expect("valid header"));
    (StatusCode::ACCEPTED, headers).into_response()
}
