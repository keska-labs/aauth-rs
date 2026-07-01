use std::sync::Arc;

use axum::Json;
use axum::extract::{Path, State};
use axum::http::{HeaderMap, StatusCode};
use axum::response::{IntoResponse, Response};

use crate::access_server::keys::AccessAuthJwtMinter;
use crate::access_server::service::{
    AccessTokenService, PolicyAccessTokenService, build_access_context,
};
use crate::deferred::AuthTokenPollOutcome;
use crate::deferred::{AccessPendingRecord, PendingStore};
use crate::keys::TestKeys;
use crate::metadata::MetadataFetcher;
use crate::policy::AccessTokenPolicy;
use crate::protocol::{AccessServerMetadata, AccessTokenExchangeRequest, JwksDocument};
use crate::server_axum::{InternalServiceError, PendingResumeInput};
use crate::signature::verify_request_signature;

#[derive(Clone)]
pub struct AccessServerConfig {
    pub keys: TestKeys,
    pub access_server_url: String,
    pub resource_url: String,
    pub person_server_url: String,
    pub access_jwks_uri: String,
    pub pending_base_url: String,
    pub pending_path: String,
    pub pending_ttl_secs: u64,
    pub fetcher: Arc<dyn MetadataFetcher>,
}

#[derive(Clone)]
pub struct AccessServerState<S>
where
    S: AccessTokenService,
{
    pub service: S,
    pub config: AccessServerConfig,
}

impl<P, S, M> AccessServerState<PolicyAccessTokenService<P, S, M>>
where
    P: AccessTokenPolicy,
    S: PendingStore<AccessPendingRecord>,
    M: AccessAuthJwtMinter + Clone,
{
    pub fn from_policy(policy: P, pending: S, minter: M, config: AccessServerConfig) -> Self {
        Self {
            service: PolicyAccessTokenService::new(policy, pending, minter, config.clone()),
            config,
        }
    }
}

pub async fn access_metadata_handler<S>(
    State(state): State<AccessServerState<S>>,
) -> Json<AccessServerMetadata>
where
    S: AccessTokenService,
{
    Json(AccessServerMetadata {
        issuer: Some(state.config.access_server_url.clone()),
        token_endpoint: format!("{}/access/aauth/token", state.config.access_server_url),
        jwks_uri: Some(state.config.access_jwks_uri.clone()),
        ..Default::default()
    })
}

pub async fn access_jwks_handler<S>(State(state): State<AccessServerState<S>>) -> Json<JwksDocument>
where
    S: AccessTokenService,
{
    Json(JwksDocument {
        keys: state.config.keys.access_server.jwk_set(),
    })
}

pub async fn access_token_exchange_handler<S>(
    State(state): State<AccessServerState<S>>,
    headers: HeaderMap,
    body: Option<Json<AccessTokenExchangeRequest>>,
) -> Response
where
    S: AccessTokenService,
{
    let authority = headers
        .get("host")
        .and_then(|h| h.to_str().ok())
        .unwrap_or("localhost")
        .to_string();

    let request = match body {
        Some(Json(b)) => b,
        None => return StatusCode::BAD_REQUEST.into_response(),
    };

    if verify_request_signature("POST", &authority, "/as/access/aauth/token", &headers).is_err() {
        return StatusCode::UNAUTHORIZED.into_response();
    }

    let ctx = match build_access_context(&state.config, &request) {
        Ok(c) => c,
        Err(_) => return StatusCode::BAD_REQUEST.into_response(),
    };

    match state.service.exchange_token(ctx).await {
        Ok(outcome) => outcome.into_response(),
        Err(e) => InternalServiceError::from(e).into_response(),
    }
}

pub async fn access_pending_poll_handler<S>(
    State(state): State<AccessServerState<S>>,
    Path(id): Path<String>,
) -> Result<AuthTokenPollOutcome, InternalServiceError>
where
    S: AccessTokenService,
{
    state
        .service
        .poll_pending(&id)
        .await
        .map_err(InternalServiceError::from)
}

pub async fn access_pending_post_handler<S>(
    State(state): State<AccessServerState<S>>,
    Path(id): Path<String>,
    PendingResumeInput(input): PendingResumeInput,
) -> Response
where
    S: AccessTokenService,
{
    match state.service.resume_pending(&id, input).await {
        Ok(outcome) => outcome.into_response(),
        Err(e) => InternalServiceError::from(e).into_response(),
    }
}
