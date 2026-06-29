use std::sync::Arc;

use axum::Json;
use axum::extract::{Path, State};
use axum::http::{HeaderMap, StatusCode};
use axum::response::{IntoResponse, Response};

use crate::jwt::{VerifiedToken, decode_resource_token_unverified};
use crate::keys::TestKeys;
use crate::metadata::MetadataFetcher;
use crate::server::access::keys::AccessAuthJwtMinter;
use crate::server::deferred::PendingInput;
use crate::server::deferred::{
    AccessPendingContext, AccessPendingRecord, ClaimsSubmission, DeferRequirement, PendingOutcome,
    PendingSnapshot, PendingStore, PollResponse, build_accepted, generate_pending_id,
    map_snapshot_to_poll_parts, pending_location,
};
use crate::server::policy::{
    AccessTokenContext, AccessTokenPolicy, AuthGrant, TokenPolicyDecision,
};
use crate::signature::verify_request_signature;
use crate::types::{
    AccessServerMetadata, AccessTokenExchangeRequest, ClarificationResponse, JwksDocument,
    TokenResponseBody,
};

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
pub struct AccessServerState<P, S, M>
where
    P: AccessTokenPolicy,
    S: PendingStore<AccessPendingRecord>,
    M: AccessAuthJwtMinter,
{
    pub policy: P,
    pub pending: S,
    pub minter: M,
    pub config: AccessServerConfig,
}

pub async fn access_metadata_handler<P, S, M>(
    State(state): State<AccessServerState<P, S, M>>,
) -> Json<AccessServerMetadata>
where
    P: AccessTokenPolicy,
    S: PendingStore<AccessPendingRecord>,
    M: AccessAuthJwtMinter,
{
    Json(AccessServerMetadata {
        issuer: Some(state.config.access_server_url.clone()),
        token_endpoint: format!("{}/access/aauth/token", state.config.access_server_url),
        jwks_uri: Some(state.config.access_jwks_uri.clone()),
        name: None,
    })
}

pub async fn access_jwks_handler<P, S, M>(
    State(state): State<AccessServerState<P, S, M>>,
) -> Json<JwksDocument>
where
    P: AccessTokenPolicy,
    S: PendingStore<AccessPendingRecord>,
    M: AccessAuthJwtMinter,
{
    Json(JwksDocument {
        keys: state.config.keys.access_server.jwk_set(),
    })
}

pub async fn access_token_exchange_handler<P, S, M>(
    State(state): State<AccessServerState<P, S, M>>,
    headers: HeaderMap,
    body: Option<Json<AccessTokenExchangeRequest>>,
) -> Response
where
    P: AccessTokenPolicy,
    S: PendingStore<AccessPendingRecord>,
    M: AccessAuthJwtMinter,
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

    let decision = match state.policy.evaluate(&ctx).await {
        Ok(d) => d,
        Err(_) => return StatusCode::INTERNAL_SERVER_ERROR.into_response(),
    };

    apply_access_decision(&state, &ctx, decision).await
}

pub async fn access_pending_poll_handler<P, S, M>(
    State(state): State<AccessServerState<P, S, M>>,
    Path(id): Path<String>,
) -> Response
where
    P: AccessTokenPolicy,
    S: PendingStore<AccessPendingRecord>,
    M: AccessAuthJwtMinter,
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

    poll_snapshot_to_response(&record.snapshot)
}

pub async fn access_pending_post_handler<P, S, M>(
    State(state): State<AccessServerState<P, S, M>>,
    Path(id): Path<String>,
    body: Option<Json<serde_json::Value>>,
) -> Response
where
    P: AccessTokenPolicy,
    S: PendingStore<AccessPendingRecord>,
    M: AccessAuthJwtMinter,
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

    let ctx = access_context_from_pending(record.context);

    let input = parse_pending_input(body.as_ref().map(|Json(v)| v));

    let decision = match state.policy.resume(&ctx, input).await {
        Ok(d) => d,
        Err(_) => return StatusCode::INTERNAL_SERVER_ERROR.into_response(),
    };

    apply_access_pending_decision(&state, &ctx, &id, decision).await
}

fn build_access_context(
    config: &AccessServerConfig,
    request: &AccessTokenExchangeRequest,
) -> Result<AccessTokenContext, crate::error::AAuthError> {
    let agent = match VerifiedToken::decode_unverified(&request.agent_token)? {
        VerifiedToken::Agent(c) => c,
        _ => {
            return Err(crate::error::AAuthError::Message(
                "agent_token must be an agent JWT".into(),
            ));
        }
    };
    let resource_claims = decode_resource_token_unverified(&request.resource_token)?;

    Ok(AccessTokenContext {
        access_server_url: config.access_server_url.clone(),
        resource_url: config.resource_url.clone(),
        person_server_url: config.person_server_url.clone(),
        agent_claims: agent,
        resource_claims,
        resource_token: request.resource_token.clone(),
        agent_token: request.agent_token.clone(),
    })
}

fn access_context_from_pending(c: AccessPendingContext) -> AccessTokenContext {
    AccessTokenContext {
        access_server_url: c.access_server_url,
        resource_url: c.resource_url,
        person_server_url: c.person_server_url,
        agent_claims: c.agent_claims,
        resource_claims: c.resource_claims,
        resource_token: c.resource_token,
        agent_token: c.agent_token,
    }
}

async fn apply_access_pending_decision<P, S, M>(
    state: &AccessServerState<P, S, M>,
    ctx: &AccessTokenContext,
    pending_id: &str,
    decision: TokenPolicyDecision,
) -> Response
where
    P: AccessTokenPolicy,
    S: PendingStore<AccessPendingRecord>,
    M: AccessAuthJwtMinter,
{
    match decision {
        TokenPolicyDecision::Grant(grant) => {
            let body = mint_access_auth(&state.minter, &state.config, grant, ctx);
            let _ = state
                .pending
                .complete(pending_id, PendingOutcome::AuthToken(body.clone()))
                .await;
            (StatusCode::OK, Json(body)).into_response()
        }
        TokenPolicyDecision::Deny(err) => {
            let _ = state
                .pending
                .complete(pending_id, PendingOutcome::Error(err.clone()))
                .await;
            (StatusCode::FORBIDDEN, Json(err)).into_response()
        }
        TokenPolicyDecision::Defer(requirement) => {
            update_access_pending_defer(state, pending_id, requirement).await
        }
    }
}

async fn update_access_pending_defer<P, S, M>(
    state: &AccessServerState<P, S, M>,
    pending_id: &str,
    requirement: DeferRequirement,
) -> Response
where
    P: AccessTokenPolicy,
    S: PendingStore<AccessPendingRecord>,
    M: AccessAuthJwtMinter,
{
    let Some(mut record) = state.pending.load(pending_id).await.ok().flatten() else {
        return StatusCode::GONE.into_response();
    };
    record.snapshot = PendingSnapshot::waiting(requirement.clone());
    if state.pending.save(pending_id, record).await.is_err() {
        return StatusCode::INTERNAL_SERVER_ERROR.into_response();
    }

    let location = pending_location(
        &state.config.pending_base_url,
        &state.config.pending_path,
        pending_id,
    );
    match build_accepted(&location, &requirement) {
        Ok(accepted) => {
            let mut response = Response::builder().status(accepted.status);
            for (k, v) in accepted.headers.iter() {
                response = response.header(k, v);
            }
            response
                .body(axum::body::Body::from(accepted.body.to_string()))
                .unwrap_or_else(|_| StatusCode::INTERNAL_SERVER_ERROR.into_response())
        }
        Err(_) => StatusCode::INTERNAL_SERVER_ERROR.into_response(),
    }
}

async fn apply_access_decision<P, S, M>(
    state: &AccessServerState<P, S, M>,
    ctx: &AccessTokenContext,
    decision: TokenPolicyDecision,
) -> Response
where
    P: AccessTokenPolicy,
    S: PendingStore<AccessPendingRecord>,
    M: AccessAuthJwtMinter,
{
    match decision {
        TokenPolicyDecision::Grant(grant) => {
            let body = mint_access_auth(&state.minter, &state.config, grant, ctx);
            (StatusCode::OK, Json(body)).into_response()
        }
        TokenPolicyDecision::Deny(err) => (StatusCode::FORBIDDEN, Json(err)).into_response(),
        TokenPolicyDecision::Defer(requirement) => {
            create_deferred_access_response(state, ctx, requirement).await
        }
    }
}

fn mint_access_auth<M: AccessAuthJwtMinter>(
    minter: &M,
    config: &AccessServerConfig,
    grant: AuthGrant,
    ctx: &AccessTokenContext,
) -> TokenResponseBody {
    let auth_jwt = minter.mint_access_auth_jwt(
        &config.access_server_url,
        &config.resource_url,
        ctx.agent_claims.identifier(),
        Some(&grant.sub),
        grant
            .scope
            .as_deref()
            .or(ctx.resource_claims.scope.as_deref()),
    );
    TokenResponseBody {
        auth_token: auth_jwt,
        expires_in: 3600,
    }
}

async fn create_deferred_access_response<P, S, M>(
    state: &AccessServerState<P, S, M>,
    ctx: &AccessTokenContext,
    requirement: DeferRequirement,
) -> Response
where
    P: AccessTokenPolicy,
    S: PendingStore<AccessPendingRecord>,
    M: AccessAuthJwtMinter,
{
    let id = generate_pending_id();
    let location = pending_location(
        &state.config.pending_base_url,
        &state.config.pending_path,
        &id,
    );
    let ttl = state.config.pending_ttl_secs;
    let record = AccessPendingRecord::new(
        id,
        AccessPendingContext {
            access_server_url: ctx.access_server_url.clone(),
            resource_url: ctx.resource_url.clone(),
            person_server_url: ctx.person_server_url.clone(),
            agent_claims: ctx.agent_claims.clone(),
            resource_claims: ctx.resource_claims.clone(),
            resource_token: ctx.resource_token.clone(),
            agent_token: ctx.agent_token.clone(),
        },
        PendingSnapshot::waiting(requirement.clone()),
        ttl,
    );

    if state.pending.create(record).await.is_err() {
        return StatusCode::INTERNAL_SERVER_ERROR.into_response();
    }

    match build_accepted(&location, &requirement) {
        Ok(accepted) => {
            let mut response = Response::builder().status(accepted.status);
            for (k, v) in accepted.headers.iter() {
                response = response.header(k, v);
            }
            response
                .body(axum::body::Body::from(accepted.body.to_string()))
                .unwrap_or_else(|_| StatusCode::INTERNAL_SERVER_ERROR.into_response())
        }
        Err(_) => StatusCode::INTERNAL_SERVER_ERROR.into_response(),
    }
}

fn poll_snapshot_to_response(snapshot: &PendingSnapshot) -> Response {
    match map_snapshot_to_poll_parts(snapshot) {
        PollResponse::OkAuthToken(body) => (StatusCode::OK, Json(body)).into_response(),
        PollResponse::OkOpaque(token) => {
            let mut headers = HeaderMap::new();
            headers.insert("AAuth-Access", token.parse().expect("valid opaque"));
            (StatusCode::OK, headers).into_response()
        }
        PollResponse::Error { status, error } => (status, Json(error)).into_response(),
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

fn parse_pending_input(body: Option<&serde_json::Value>) -> PendingInput {
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
