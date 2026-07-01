use std::sync::Arc;

use axum::Json;
use axum::extract::{Path, State};
use axum::http::{HeaderMap, StatusCode};
use axum::response::{IntoResponse, Response};

use crate::deferred::AuthTokenPollOutcome;
use crate::deferred::{PendingStore, PersonPendingRecord};
use crate::keys::TestKeys;
use crate::metadata::MetadataFetcher;
use crate::person_server::keys::AuthJwtMinter;
use crate::person_server::orchestrate::{PersonOrchestrateConfig, verify_person_token_request};
use crate::person_server::service::{PersonTokenService, PolicyPersonTokenService};
use crate::policy::PersonTokenPolicy;
use crate::protocol::{JwksDocument, PersonServerMetadata, TokenExchangeRequest};
use crate::server_axum::{InternalServiceError, PendingResumeInput};
use crate::signature::verify_request_signature;

#[derive(Clone)]
pub struct PersonServerConfig {
    pub keys: TestKeys,
    pub person_server_url: String,
    pub resource_url: String,
    pub agent_url: String,
    pub person_jwks_uri: String,
    pub interaction_url: String,
    pub pending_base_url: String,
    pub pending_path: String,
    pub pending_ttl_secs: u64,
    pub fetcher: Arc<dyn MetadataFetcher>,
    pub http_client: reqwest::Client,
    /// Max seconds for federation pending polls (default 300).
    pub federation_poll_max_secs: Option<u64>,
}

impl PersonServerConfig {
    pub fn orchestrate(&self) -> PersonOrchestrateConfig {
        PersonOrchestrateConfig {
            person_server_url: self.person_server_url.clone(),
            resource_url: self.resource_url.clone(),
            interaction_url: self.interaction_url.clone(),
            pending_base_url: self.pending_base_url.clone(),
            pending_path: self.pending_path.clone(),
            pending_ttl_secs: self.pending_ttl_secs,
            fetcher: Arc::clone(&self.fetcher),
            http_client: self.http_client.clone(),
            federation: crate::person_server::federation::FederationConfig {
                fetcher: Arc::clone(&self.fetcher),
            },
            federation_poll_max_secs: self.federation_poll_max_secs,
            keys: self.keys.clone(),
            person_server_signing_jwk: self.keys.person_server.signing_jwk(),
        }
    }
}

#[derive(Clone)]
pub struct PersonServerState<S>
where
    S: PersonTokenService,
{
    pub service: S,
    pub config: PersonServerConfig,
}

impl<P, S, M> PersonServerState<PolicyPersonTokenService<P, S, M>>
where
    P: PersonTokenPolicy,
    S: PendingStore<PersonPendingRecord>,
    M: AuthJwtMinter + Clone,
{
    pub fn from_policy(policy: P, pending: S, minter: M, config: PersonServerConfig) -> Self {
        Self {
            service: PolicyPersonTokenService::new(policy, pending, minter, config.clone()),
            config,
        }
    }
}

pub async fn person_metadata_handler<S>(
    State(state): State<PersonServerState<S>>,
) -> Json<PersonServerMetadata>
where
    S: PersonTokenService,
{
    Json(PersonServerMetadata {
        issuer: Some(state.config.person_server_url.clone()),
        token_endpoint: format!("{}/aauth/token", state.config.person_server_url),
        jwks_uri: Some(state.config.person_jwks_uri.clone()),
        interaction_endpoint: Some(state.config.interaction_url.clone()),
        ..Default::default()
    })
}

pub async fn person_jwks_handler<S>(State(state): State<PersonServerState<S>>) -> Json<JwksDocument>
where
    S: PersonTokenService,
{
    Json(JwksDocument {
        keys: state.config.keys.person_server.jwk_set(),
    })
}

pub async fn token_exchange_handler<S>(
    State(state): State<PersonServerState<S>>,
    headers: HeaderMap,
    body: Option<Json<TokenExchangeRequest>>,
) -> Response
where
    S: PersonTokenService,
{
    let orch = state.config.orchestrate();
    let authority = headers
        .get("host")
        .and_then(|h| h.to_str().ok())
        .unwrap_or("localhost")
        .to_string();

    let verified_sig = match verify_request_signature("POST", &authority, "/aauth/token", &headers)
    {
        Ok(v) => v,
        Err(_) => return StatusCode::UNAUTHORIZED.into_response(),
    };

    let request = match body {
        Some(Json(b)) => b,
        None => return StatusCode::BAD_REQUEST.into_response(),
    };

    let resource_token = request.resource_token.clone();
    let ctx = match verify_person_token_request(
        &orch,
        &verified_sig.jwt,
        &verified_sig.thumbprint,
        &resource_token,
        request,
    )
    .await
    {
        Ok(c) => c,
        Err(_) => return StatusCode::UNAUTHORIZED.into_response(),
    };

    match state.service.exchange_token(ctx, &verified_sig.jwt).await {
        Ok(outcome) => outcome.into_response(),
        Err(e) => InternalServiceError::from(e).into_response(),
    }
}

pub async fn pending_poll_handler<S>(
    State(state): State<PersonServerState<S>>,
    Path(id): Path<String>,
) -> Result<AuthTokenPollOutcome, InternalServiceError>
where
    S: PersonTokenService,
{
    state
        .service
        .poll_pending(&id)
        .await
        .map_err(InternalServiceError::from)
}

pub async fn pending_post_handler<S>(
    State(state): State<PersonServerState<S>>,
    Path(id): Path<String>,
    PendingResumeInput(input): PendingResumeInput,
) -> Response
where
    S: PersonTokenService,
{
    match state.service.resume_pending(&id, input).await {
        Ok(outcome) => outcome.into_response(),
        Err(e) => InternalServiceError::from(e).into_response(),
    }
}

pub use pending_post_handler as pending_clarification_post_handler;
pub use token_exchange_handler as token_exchange_deferred_handler;
