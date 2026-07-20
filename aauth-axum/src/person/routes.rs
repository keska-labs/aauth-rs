use axum::Json;
use axum::Router;
use axum::extract::{FromRef, OriginalUri, Path, Query, State};
use axum::http::{HeaderMap, StatusCode};
use axum::response::{IntoResponse, Response};
use axum::routing::{get, post};
use serde::Deserialize;

use aauth::AuthTokenPollOutcome;
use aauth::PendingStore;
use aauth::PersonPendingRecord;
use aauth::PersonServerConfig;
use aauth::person_server::keys::AuthJwtMinter;
use aauth::person_server::orchestrate::verify_person_token_request;
use aauth::person_server::service::{PersonTokenService, PolicyPersonTokenService};
use aauth::policy::PersonTokenPolicy;
use aauth::protocol::{JwksDocument, PersonServerMetadata, TokenExchangeRequest};
use aauth::signature::verify_request_signature;

use crate::{AauthResponse, InternalServiceError, PendingResumeInput};

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
    OriginalUri(uri): OriginalUri,
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

    let verified_sig = match verify_request_signature("POST", &authority, uri.path(), &headers) {
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
        Ok(outcome) => AauthResponse(outcome).into_response(),
        Err(e) => InternalServiceError::from(e).into_response(),
    }
}

pub async fn pending_poll_handler<S>(
    State(state): State<PersonServerState<S>>,
    Path(id): Path<String>,
) -> Result<AauthResponse<AuthTokenPollOutcome>, InternalServiceError>
where
    S: PersonTokenService,
{
    state
        .service
        .poll_pending(&id)
        .await
        .map(AauthResponse)
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
        Ok(outcome) => AauthResponse(outcome).into_response(),
        Err(e) => InternalServiceError::from(e).into_response(),
    }
}

pub use pending_post_handler as pending_clarification_post_handler;
pub use token_exchange_handler as token_exchange_deferred_handler;

#[derive(Debug, Deserialize)]
pub struct InteractionStartQuery {
    pub code: String,
}

#[derive(Debug, Deserialize)]
pub struct InteractionCallbackQuery {
    pub id: String,
    pub error: Option<String>,
}

pub async fn interaction_start_handler<S>(
    State(state): State<PersonServerState<S>>,
    Query(query): Query<InteractionStartQuery>,
) -> Response
where
    S: PersonTokenService,
{
    match state.service.begin_interaction(&query.code).await {
        Ok(outcome) => AauthResponse(outcome).into_response(),
        Err(e) => InternalServiceError::from(e).into_response(),
    }
}

pub async fn interaction_callback_handler<S>(
    State(state): State<PersonServerState<S>>,
    Query(query): Query<InteractionCallbackQuery>,
) -> Response
where
    S: PersonTokenService,
{
    match state
        .service
        .resolve_interaction_callback(&query.id, query.error.as_deref())
        .await
    {
        Ok(outcome) => AauthResponse(outcome).into_response(),
        Err(e) => InternalServiceError::from(e).into_response(),
    }
}

/// Canonical Person Server routes.
///
/// Mounts:
/// - `GET /.well-known/aauth-person.json`
/// - `GET /auth/jwks`
/// - `POST /aauth/token`
/// - `GET|POST /pending/{id}`
/// - `GET /interact`
/// - `GET /interact/callback`
///
/// Merge into an app whose state implements [`FromRef`] to [`PersonServerState`].
pub fn person_router<AppState, Svc>() -> Router<AppState>
where
    AppState: Clone + Send + Sync + 'static,
    Svc: PersonTokenService + 'static,
    PersonServerState<Svc>: FromRef<AppState>,
{
    Router::new()
        .route(
            "/.well-known/aauth-person.json",
            get(person_metadata_handler::<Svc>),
        )
        .route("/auth/jwks", get(person_jwks_handler::<Svc>))
        .route("/aauth/token", post(token_exchange_handler::<Svc>))
        .route(
            "/pending/{id}",
            get(pending_poll_handler::<Svc>).post(pending_post_handler::<Svc>),
        )
        .route("/interact", get(interaction_start_handler::<Svc>))
        .route(
            "/interact/callback",
            get(interaction_callback_handler::<Svc>),
        )
}
