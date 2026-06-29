use std::collections::HashMap;
use std::sync::{Arc, Mutex};

use axum::Json;
use axum::extract::{Path, State};
use axum::http::{HeaderMap, StatusCode};
use axum::response::{IntoResponse, Response};

use crate::keys::TestKeys;
use crate::server::InteractionManager;
use crate::server::keys::mint_auth_jwt;
use crate::types::{
    AuthServerMetadata, ClarificationChallenge, ClarificationResponse, JwksDocument,
    MetadataDocument, TokenExchangeRequest, TokenResponseBody,
};

#[derive(Clone)]
pub struct AuthServerState {
    pub keys: TestKeys,
    pub auth_server_url: String,
    pub resource_url: String,
    pub agent_url: String,
    pub agent_jwks_uri: String,
    pub auth_jwks_uri: String,
    pub interaction_manager: Arc<InteractionManager>,
    pub deferred_mode: bool,
    pub pending_id_capture: Option<Arc<Mutex<Option<String>>>>,
    pub clarification_state: Option<Arc<Mutex<HashMap<String, bool>>>>,
    pub clarification_prompt: bool,
}

pub async fn person_metadata_handler(
    State(state): State<AuthServerState>,
) -> Json<AuthServerMetadata> {
    Json(AuthServerMetadata {
        token_endpoint: format!("{}/aauth/token", state.auth_server_url),
        jwks_uri: Some(state.auth_jwks_uri.clone()),
    })
}

pub async fn jwks_handler(State(state): State<AuthServerState>) -> Json<JwksDocument> {
    Json(JwksDocument {
        keys: state.keys.auth_server.jwk_set(),
    })
}

pub async fn agent_metadata_handler(
    State(state): State<AuthServerState>,
) -> Json<MetadataDocument> {
    Json(MetadataDocument {
        jwks_uri: state.agent_jwks_uri.clone(),
        extra: Default::default(),
    })
}

pub async fn agent_jwks_handler(State(state): State<AuthServerState>) -> Json<JwksDocument> {
    Json(JwksDocument {
        keys: state.keys.agent_root.jwk_set(),
    })
}

pub async fn token_exchange_handler(
    State(state): State<AuthServerState>,
    body: Option<Json<TokenExchangeRequest>>,
) -> Result<Json<TokenResponseBody>, StatusCode> {
    let _request = body.map(|Json(b)| b);

    let auth_jwt = mint_auth_jwt(
        &state.keys,
        &state.auth_server_url,
        &state.resource_url,
        &state.agent_url,
        Some("user-123"),
        None,
    );

    Ok(Json(TokenResponseBody {
        auth_token: auth_jwt,
        expires_in: 3600,
    }))
}

pub async fn token_exchange_deferred_handler(
    State(state): State<AuthServerState>,
    body: Option<Json<TokenExchangeRequest>>,
) -> Result<Response, StatusCode> {
    let _request = body.map(|Json(b)| b);

    if !state.deferred_mode {
        return token_exchange_handler(State(state), None)
            .await
            .map(|json| json.into_response());
    }

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
    State(state): State<AuthServerState>,
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
    State(state): State<AuthServerState>,
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

fn pending_poll_response(state: &AuthServerState, id: &str) -> Response {
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
