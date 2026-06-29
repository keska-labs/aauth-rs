use std::collections::HashMap;
use std::sync::{Arc, Mutex};

use axum::Json;
use axum::extract::{Path, State};
use axum::http::{HeaderMap, StatusCode};
use axum::response::{IntoResponse, Response};

use crate::keys::TestKeys;
use crate::metadata::MetadataFetcher;
use crate::server::interaction::InteractionManager;
use crate::server::person::federation::fulfill_token_exchange;
use crate::types::{
    ClarificationChallenge, ClarificationResponse, JwksDocument, PersonServerMetadata,
    TokenExchangeRequest, TokenResponseBody,
};

#[derive(Clone)]
pub struct PersonServerState {
    pub keys: TestKeys,
    pub person_server_url: String,
    pub resource_url: String,
    pub agent_url: String,
    pub person_jwks_uri: String,
    pub interaction_manager: Arc<InteractionManager>,
    pub deferred_mode: bool,
    pub pending_id_capture: Option<Arc<Mutex<Option<String>>>>,
    pub clarification_state: Option<Arc<Mutex<HashMap<String, bool>>>>,
    pub clarification_prompt: bool,
    pub fetcher: Arc<dyn MetadataFetcher>,
    pub http_client: reqwest::Client,
}

pub async fn person_metadata_handler(
    State(state): State<PersonServerState>,
) -> Json<PersonServerMetadata> {
    Json(PersonServerMetadata {
        issuer: Some(state.person_server_url.clone()),
        token_endpoint: format!("{}/aauth/token", state.person_server_url),
        jwks_uri: Some(state.person_jwks_uri.clone()),
        name: None,
        permission_endpoint: None,
        interaction_endpoint: None,
        mission_endpoint: None,
    })
}

pub async fn person_jwks_handler(State(state): State<PersonServerState>) -> Json<JwksDocument> {
    Json(JwksDocument {
        keys: state.keys.person_server.jwk_set(),
    })
}

pub async fn token_exchange_handler(
    State(state): State<PersonServerState>,
    body: Option<Json<TokenExchangeRequest>>,
) -> Result<Json<TokenResponseBody>, StatusCode> {
    let request = body.map(|Json(b)| b);
    let resource_token = request
        .as_ref()
        .map(|r| r.resource_token.as_str())
        .ok_or(StatusCode::BAD_REQUEST)?;

    let response = fulfill_token_exchange(
        &state.keys,
        &state.person_server_url,
        &state.resource_url,
        &state.agent_url,
        resource_token,
        Arc::clone(&state.fetcher),
        &state.http_client,
    )
    .await
    .map_err(|_| StatusCode::UNAUTHORIZED)?;

    Ok(Json(response))
}

pub async fn token_exchange_deferred_handler(
    State(state): State<PersonServerState>,
    body: Option<Json<TokenExchangeRequest>>,
) -> Result<Response, StatusCode> {
    if !state.deferred_mode {
        return token_exchange_handler(State(state), body)
            .await
            .map(|json| json.into_response());
    }

    let _request = body.map(|Json(b)| b);

    let (headers, pending) = state.interaction_manager.create_pending();

    if let Some(capture) = &state.pending_id_capture {
        *capture.lock().unwrap() = Some(pending.id.clone());
    }

    let mut response = Response::builder().status(StatusCode::ACCEPTED);
    for (name, value) in headers {
        response = response.header(name, value);
    }
    Ok(response
        .body(axum::body::Body::empty())
        .expect("valid response"))
}

pub async fn pending_poll_handler(
    State(state): State<PersonServerState>,
    Path(id): Path<String>,
) -> Response {
    if state.clarification_prompt {
        if let Some(clarification_state) = &state.clarification_state {
            let answered = clarification_state
                .lock()
                .unwrap()
                .get(&id)
                .copied()
                .unwrap_or(false);
            if !answered {
                return (
                    StatusCode::ACCEPTED,
                    [("content-type", "application/json")],
                    Json(ClarificationChallenge {
                        clarification: "What is your purpose?".into(),
                    }),
                )
                    .into_response();
            }
        }
    }

    pending_poll_response(&state, &id)
}

pub async fn pending_clarification_post_handler(
    State(state): State<PersonServerState>,
    Path(id): Path<String>,
    body: Json<ClarificationResponse>,
) -> Response {
    let _ = body.0;
    if let Some(clarification_state) = &state.clarification_state {
        clarification_state
            .lock()
            .unwrap()
            .insert(id, true);
    }
    StatusCode::ACCEPTED.into_response()
}

fn pending_poll_response(state: &PersonServerState, id: &str) -> Response {
    let manager = &state.interaction_manager;
    let Some(pending) = manager.get_pending(id) else {
        return StatusCode::GONE.into_response();
    };

    if let Some(result) = pending.result.lock().unwrap().clone() {
        match result {
            Ok(value) => {
                manager.remove(id);
                return (StatusCode::OK, Json(value)).into_response();
            }
            Err(err) => {
                manager.remove(id);
                return (StatusCode::INTERNAL_SERVER_ERROR, err).into_response();
            }
        }
    }

    let mut headers = HeaderMap::new();
    headers.insert("Retry-After", "0".parse().expect("valid header"));
    headers.insert("Cache-Control", "no-store".parse().expect("valid header"));
    (StatusCode::ACCEPTED, headers).into_response()
}
