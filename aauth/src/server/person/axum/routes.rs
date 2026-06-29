use std::sync::Arc;

use axum::Json;
use axum::extract::{Path, State};
use axum::http::{HeaderMap, StatusCode};
use axum::response::{IntoResponse, Response};

use crate::keys::TestKeys;
use crate::metadata::MetadataFetcher;
use crate::server::deferred::PendingInput;
use crate::server::deferred::{
    ClaimsSubmission, DeferRequirement, FederationPendingState, PendingContext, PendingKind,
    PendingOutcome, PendingRecord, PendingSnapshot, PendingStore, PersonPendingContext,
    PollResponse, ServerPollOptions, ServerPollOutcome, build_accepted, generate_pending_id,
    map_snapshot_to_poll_parts, pending_location, poll_pending_http, post_pending_input,
};
use crate::server::person::federation::{
    FederationOutcome, federate_to_access_server, verify_federated_auth_token,
};
use crate::server::person::keys::AuthJwtMinter;
use crate::server::person::orchestrate::{
    PersonOrchestrateConfig, mint_person_auth, verify_person_token_request,
};
use crate::server::policy::{PersonTokenContext, PersonTokenDecision, PersonTokenPolicy};
use crate::signature::verify_request_signature;
use crate::types::{
    ClarificationResponse, JwksDocument, PersonServerMetadata, TokenExchangeRequest,
};

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
            federation: crate::server::person::federation::FederationConfig {
                fetcher: Arc::clone(&self.fetcher),
            },
            federation_poll_max_secs: self.federation_poll_max_secs,
        }
    }
}

#[derive(Clone)]
pub struct PersonServerState<P, S, M>
where
    P: PersonTokenPolicy,
    S: PendingStore,
    M: AuthJwtMinter,
{
    pub policy: P,
    pub pending: S,
    pub minter: M,
    pub config: PersonServerConfig,
}

pub async fn person_metadata_handler<P, S, M>(
    State(state): State<PersonServerState<P, S, M>>,
) -> Json<PersonServerMetadata>
where
    P: PersonTokenPolicy,
    S: PendingStore,
    M: AuthJwtMinter,
{
    Json(PersonServerMetadata {
        issuer: Some(state.config.person_server_url.clone()),
        token_endpoint: format!("{}/aauth/token", state.config.person_server_url),
        jwks_uri: Some(state.config.person_jwks_uri.clone()),
        name: None,
        permission_endpoint: None,
        interaction_endpoint: Some(state.config.interaction_url.clone()),
        mission_endpoint: None,
    })
}

pub async fn person_jwks_handler<P, S, M>(
    State(state): State<PersonServerState<P, S, M>>,
) -> Json<JwksDocument>
where
    P: PersonTokenPolicy,
    S: PendingStore,
    M: AuthJwtMinter,
{
    Json(JwksDocument {
        keys: state.config.keys.person_server.jwk_set(),
    })
}

pub async fn token_exchange_handler<P, S, M>(
    State(state): State<PersonServerState<P, S, M>>,
    headers: HeaderMap,
    body: Option<Json<TokenExchangeRequest>>,
) -> Response
where
    P: PersonTokenPolicy,
    S: PendingStore,
    M: AuthJwtMinter,
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
    let ctx = match verify_person_token_request(&orch, &verified_sig.jwt, &resource_token, request)
        .await
    {
        Ok(c) => c,
        Err(_) => return StatusCode::UNAUTHORIZED.into_response(),
    };

    let decision = match state.policy.evaluate(&ctx).await {
        Ok(d) => d,
        Err(_) => return StatusCode::INTERNAL_SERVER_ERROR.into_response(),
    };

    apply_person_decision(&state, &orch, &ctx, decision, &verified_sig.jwt).await
}

pub async fn pending_poll_handler<P, S, M>(
    State(state): State<PersonServerState<P, S, M>>,
    Path(id): Path<String>,
) -> Response
where
    P: PersonTokenPolicy,
    S: PendingStore,
    M: AuthJwtMinter,
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

pub async fn pending_post_handler<P, S, M>(
    State(state): State<PersonServerState<P, S, M>>,
    Path(id): Path<String>,
    body: Option<Json<serde_json::Value>>,
) -> Response
where
    P: PersonTokenPolicy,
    S: PendingStore,
    M: AuthJwtMinter,
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

    let PersonPendingContext {
        person_server_url,
        resource_url,
        agent_claims,
        resource_claims,
        exchange_request,
        agent_token,
        federation,
    } = match record.context {
        PendingContext::Person(c) => c,
        _ => return StatusCode::BAD_REQUEST.into_response(),
    };

    let input = parse_pending_input(body.as_ref().map(|Json(v)| v));
    let orch = state.config.orchestrate();

    if let Some(fed) = federation {
        return handle_federated_pending_post(
            &state,
            &orch,
            &id,
            &fed,
            &agent_token,
            &orch.resource_url,
            input,
        )
        .await;
    }

    let ctx = PersonTokenContext {
        person_server_url,
        resource_url,
        agent_claims,
        resource_claims,
        exchange_request,
    };

    let decision = match state.policy.resume(&ctx, input).await {
        Ok(d) => d,
        Err(_) => return StatusCode::INTERNAL_SERVER_ERROR.into_response(),
    };

    apply_person_pending_decision(&state, &orch, &ctx, &id, decision, &agent_token).await
}

async fn apply_person_pending_decision<P, S, M>(
    state: &PersonServerState<P, S, M>,
    orch: &PersonOrchestrateConfig,
    ctx: &PersonTokenContext,
    pending_id: &str,
    decision: PersonTokenDecision,
    agent_jwt: &str,
) -> Response
where
    P: PersonTokenPolicy,
    S: PendingStore,
    M: AuthJwtMinter,
{
    match decision {
        PersonTokenDecision::Grant(grant) => {
            let body = mint_person_auth(&state.minter, orch, &grant, &ctx.agent_claims.iss);
            let _ = state
                .pending
                .complete(pending_id, PendingOutcome::AuthToken(body.clone()))
                .await;
            (StatusCode::OK, Json(body)).into_response()
        }
        PersonTokenDecision::Federate => {
            match federate_to_access_server(
                &orch.http_client,
                Arc::clone(&orch.fetcher),
                &state.minter,
                &orch.person_server_url,
                &orch.resource_url,
                &ctx.exchange_request.resource_token,
                agent_jwt,
            )
            .await
            {
                Ok(FederationOutcome::Complete(body)) => {
                    let _ = state
                        .pending
                        .complete(pending_id, PendingOutcome::AuthToken(body.clone()))
                        .await;
                    (StatusCode::OK, Json(body)).into_response()
                }
                Ok(FederationOutcome::Deferred {
                    requirement,
                    as_pending_url,
                    access_server_url,
                }) => {
                    create_federated_deferred_response(
                        state,
                        orch,
                        ctx,
                        Some(pending_id),
                        requirement,
                        FederationPendingState {
                            access_server_url,
                            as_pending_url,
                        },
                        agent_jwt,
                    )
                    .await
                }
                Err(_) => StatusCode::UNAUTHORIZED.into_response(),
            }
        }
        PersonTokenDecision::Deny(err) => {
            let _ = state
                .pending
                .complete(pending_id, PendingOutcome::Error(err.clone()))
                .await;
            (StatusCode::FORBIDDEN, Json(err)).into_response()
        }
        PersonTokenDecision::Defer(requirement) => {
            update_person_pending_defer(state, orch, pending_id, requirement).await
        }
    }
}

async fn update_person_pending_defer<P, S, M>(
    state: &PersonServerState<P, S, M>,
    orch: &PersonOrchestrateConfig,
    pending_id: &str,
    requirement: DeferRequirement,
) -> Response
where
    P: PersonTokenPolicy,
    S: PendingStore,
    M: AuthJwtMinter,
{
    let Some(mut record) = state.pending.load(pending_id).await.ok().flatten() else {
        return StatusCode::GONE.into_response();
    };
    record.snapshot = PendingSnapshot::waiting(requirement.clone());
    if state.pending.save(pending_id, record).await.is_err() {
        return StatusCode::INTERNAL_SERVER_ERROR.into_response();
    }

    let location = pending_location(&orch.pending_base_url, &orch.pending_path, pending_id);
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

async fn apply_person_decision<P, S, M>(
    state: &PersonServerState<P, S, M>,
    orch: &PersonOrchestrateConfig,
    ctx: &PersonTokenContext,
    decision: PersonTokenDecision,
    agent_jwt: &str,
) -> Response
where
    P: PersonTokenPolicy,
    S: PendingStore,
    M: AuthJwtMinter,
{
    match decision {
        PersonTokenDecision::Grant(grant) => {
            let body = mint_person_auth(&state.minter, orch, &grant, &ctx.agent_claims.iss);
            (StatusCode::OK, Json(body)).into_response()
        }
        PersonTokenDecision::Federate => match federate_to_access_server(
            &orch.http_client,
            Arc::clone(&orch.fetcher),
            &state.minter,
            &orch.person_server_url,
            &orch.resource_url,
            &ctx.exchange_request.resource_token,
            agent_jwt,
        )
        .await
        {
            Ok(FederationOutcome::Complete(body)) => (StatusCode::OK, Json(body)).into_response(),
            Ok(FederationOutcome::Deferred {
                requirement,
                as_pending_url,
                access_server_url,
            }) => {
                create_federated_deferred_response(
                    state,
                    orch,
                    ctx,
                    None,
                    requirement,
                    FederationPendingState {
                        access_server_url,
                        as_pending_url,
                    },
                    agent_jwt,
                )
                .await
            }
            Err(_) => StatusCode::UNAUTHORIZED.into_response(),
        },
        PersonTokenDecision::Deny(err) => (StatusCode::FORBIDDEN, Json(err)).into_response(),
        PersonTokenDecision::Defer(requirement) => {
            create_deferred_person_response(state, orch, ctx, requirement, agent_jwt).await
        }
    }
}

async fn create_federated_deferred_response<P, S, M>(
    state: &PersonServerState<P, S, M>,
    orch: &PersonOrchestrateConfig,
    ctx: &PersonTokenContext,
    pending_id: Option<&str>,
    requirement: DeferRequirement,
    federation: FederationPendingState,
    agent_jwt: &str,
) -> Response
where
    P: PersonTokenPolicy,
    S: PendingStore,
    M: AuthJwtMinter,
{
    let id = pending_id
        .map(str::to_string)
        .unwrap_or_else(generate_pending_id);
    let location = pending_location(&orch.pending_base_url, &orch.pending_path, &id);

    let person_ctx = PersonPendingContext {
        person_server_url: ctx.person_server_url.clone(),
        resource_url: ctx.resource_url.clone(),
        agent_claims: ctx.agent_claims.clone(),
        resource_claims: ctx.resource_claims.clone(),
        exchange_request: ctx.exchange_request.clone(),
        agent_token: agent_jwt.to_string(),
        federation: Some(federation),
    };

    if pending_id.is_some() {
        let Some(mut record) = state.pending.load(&id).await.ok().flatten() else {
            return StatusCode::GONE.into_response();
        };
        record.context = PendingContext::Person(person_ctx);
        record.snapshot = PendingSnapshot::waiting(requirement.clone());
        if state.pending.save(&id, record).await.is_err() {
            return StatusCode::INTERNAL_SERVER_ERROR.into_response();
        }
    } else {
        let record = PendingRecord::new(
            id.clone(),
            PendingKind::PersonToken,
            PendingContext::Person(person_ctx),
            PendingSnapshot::waiting(requirement.clone()),
            orch.pending_ttl_secs,
        );
        if state.pending.create(record).await.is_err() {
            return StatusCode::INTERNAL_SERVER_ERROR.into_response();
        }
    }

    build_accepted_response(&location, &requirement)
}

async fn handle_federated_pending_post<P, S, M>(
    state: &PersonServerState<P, S, M>,
    orch: &PersonOrchestrateConfig,
    pending_id: &str,
    federation: &FederationPendingState,
    agent_token: &str,
    resource_url: &str,
    input: PendingInput,
) -> Response
where
    P: PersonTokenPolicy,
    S: PendingStore,
    M: AuthJwtMinter,
{
    if matches!(input, PendingInput::Cancelled) {
        let err = crate::types::AAuthProtocolError {
            error: "access_denied".into(),
            error_description: Some("Request cancelled".into()),
            error_uri: None,
        };
        let _ = state
            .pending
            .complete(pending_id, PendingOutcome::Error(err.clone()))
            .await;
        return (StatusCode::FORBIDDEN, Json(err)).into_response();
    }

    let post_outcome =
        match post_pending_input(&orch.http_client, &federation.as_pending_url, &input).await {
            Ok(outcome) => outcome,
            Err(_) => return StatusCode::BAD_GATEWAY.into_response(),
        };

    let poll_outcome = if let Some(body) = post_outcome {
        ServerPollOutcome::AuthToken(body)
    } else {
        match poll_pending_http(
            &orch.http_client,
            ServerPollOptions {
                location_url: federation.as_pending_url.clone(),
                max_poll_duration_secs: orch.federation_poll_max_secs,
                prefer_wait: None,
            },
            &federation.access_server_url,
        )
        .await
        {
            Ok(outcome) => outcome,
            Err(_) => return StatusCode::BAD_GATEWAY.into_response(),
        }
    };

    match poll_outcome {
        ServerPollOutcome::AuthToken(body) => {
            if verify_federated_auth_token(
                &body.auth_token,
                &federation.access_server_url,
                resource_url,
                agent_token,
                Arc::clone(&orch.fetcher),
            )
            .await
            .is_err()
            {
                return StatusCode::UNAUTHORIZED.into_response();
            }
            let _ = state
                .pending
                .complete(pending_id, PendingOutcome::AuthToken(body.clone()))
                .await;
            (StatusCode::OK, Json(body)).into_response()
        }
        ServerPollOutcome::Deferred {
            requirement,
            location_url,
        } => {
            let Some(mut record) = state.pending.load(pending_id).await.ok().flatten() else {
                return StatusCode::GONE.into_response();
            };
            record.snapshot = PendingSnapshot::waiting(requirement.clone());
            if let PendingContext::Person(ref mut ctx) = record.context {
                ctx.federation = Some(FederationPendingState {
                    access_server_url: federation.access_server_url.clone(),
                    as_pending_url: location_url,
                });
            }
            if state.pending.save(pending_id, record).await.is_err() {
                return StatusCode::INTERNAL_SERVER_ERROR.into_response();
            }
            let location = pending_location(&orch.pending_base_url, &orch.pending_path, pending_id);
            build_accepted_response(&location, &requirement)
        }
        ServerPollOutcome::Error(err) => {
            let _ = state
                .pending
                .complete(pending_id, PendingOutcome::Error(err.clone()))
                .await;
            (StatusCode::FORBIDDEN, Json(err)).into_response()
        }
        ServerPollOutcome::Gone => {
            let _ = state.pending.remove(pending_id).await;
            StatusCode::GONE.into_response()
        }
    }
}

fn build_accepted_response(location: &str, requirement: &DeferRequirement) -> Response {
    match build_accepted(location, requirement) {
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

async fn create_deferred_person_response<P, S, M>(
    state: &PersonServerState<P, S, M>,
    orch: &PersonOrchestrateConfig,
    ctx: &PersonTokenContext,
    requirement: DeferRequirement,
    agent_jwt: &str,
) -> Response
where
    P: PersonTokenPolicy,
    S: PendingStore,
    M: AuthJwtMinter,
{
    let id = generate_pending_id();
    let location = pending_location(&orch.pending_base_url, &orch.pending_path, &id);
    let record = PendingRecord::new(
        id,
        PendingKind::PersonToken,
        PendingContext::Person(PersonPendingContext {
            person_server_url: ctx.person_server_url.clone(),
            resource_url: ctx.resource_url.clone(),
            agent_claims: ctx.agent_claims.clone(),
            resource_claims: ctx.resource_claims.clone(),
            exchange_request: ctx.exchange_request.clone(),
            agent_token: agent_jwt.to_string(),
            federation: None,
        }),
        PendingSnapshot::waiting(requirement.clone()),
        orch.pending_ttl_secs,
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

pub use pending_post_handler as pending_clarification_post_handler;
pub use token_exchange_handler as token_exchange_deferred_handler;
