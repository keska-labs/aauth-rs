use axum::Json;
use axum::Router;
use axum::extract::{FromRef, OriginalUri, Path, Query, State};
use axum::http::header::HOST;
use axum::http::{HeaderMap, StatusCode};
use axum::response::{IntoResponse, Response};
use axum::routing::{get, post};
use serde::Deserialize;

use aauth::AccessServerClient;
use aauth::AuthTokenPollOutcome;
use aauth::PersonServerConfig;
use aauth::metadata::MetadataFetcher;
use aauth::person_server::service::PersonTokenService;
use aauth::protocol::{JwksDocument, PersonServerMetadata, TokenExchangeRequest};
use httpsig_key::{VerifyOptions, verify};

use crate::{AauthResponse, InternalServiceError, PendingResumeInput};

#[derive(Clone)]
pub struct PersonServerState<
    S: PersonTokenService,
    F: MetadataFetcher = aauth::StaticMetadataFetcher,
    C: AccessServerClient = aauth::AbsentAccessServerClient,
> {
    pub service: S,
    pub config: PersonServerConfig<F, C>,
}

#[cfg(feature = "policy")]
impl<P, S, M, F, C>
    PersonServerState<aauth_policy::PolicyPersonTokenService<P, S, M, F, C>, F, C>
where
    P: aauth_policy::PersonTokenPolicy,
    S: aauth_policy::PendingStore<aauth_policy::PersonPendingRecord>,
    M: aauth::person_server::keys::PersonAuthJwtMinter + Clone,
    F: MetadataFetcher + Clone + 'static,
    C: AccessServerClient + Clone + 'static,
{
    pub fn from_policy(
        policy: P,
        pending: S,
        minter: M,
        config: PersonServerConfig<F, C>,
    ) -> Self {
        Self {
            service: aauth_policy::PolicyPersonTokenService::new(
                policy,
                pending,
                minter,
                config.clone(),
            ),
            config,
        }
    }
}

pub async fn person_metadata_handler<S, F, C>(
    State(state): State<PersonServerState<S, F, C>>,
) -> Json<PersonServerMetadata>
where
    S: PersonTokenService,
    F: MetadataFetcher,
    C: AccessServerClient,
{
    // `person_server_url` is the logical issuer; endpoint URLs use the reachable base.
    let base = state.config.pending_base_url.trim_end_matches('/');
    Json(PersonServerMetadata {
        issuer: Some(state.config.person_server_url.clone()),
        token_endpoint: format!("{base}/aauth/token"),
        jwks_uri: Some(state.config.person_jwks_uri.clone()),
        interaction_endpoint: Some(state.config.interaction_url.clone()),
        ..Default::default()
    })
}

pub async fn person_jwks_handler<S, F, C>(
    State(state): State<PersonServerState<S, F, C>>,
) -> Json<JwksDocument>
where
    S: PersonTokenService,
    F: MetadataFetcher,
    C: AccessServerClient,
{
    Json(JwksDocument {
        keys: state.config.keys.person_server.jwk_set(),
    })
}

pub async fn token_exchange_handler<S, F, C>(
    State(state): State<PersonServerState<S, F, C>>,
    OriginalUri(uri): OriginalUri,
    headers: HeaderMap,
    body: Option<Json<TokenExchangeRequest>>,
) -> Response
where
    S: PersonTokenService,
    F: MetadataFetcher,
    C: AccessServerClient,
{
    let authority = headers
        .get(HOST)
        .and_then(|h| h.to_str().ok())
        .unwrap_or("localhost")
        .to_string();

    let verified = match verify(
        "POST",
        &authority,
        uri.path(),
        &headers,
        &VerifyOptions::default(),
    ) {
        Ok(v) => v,
        Err(_) => return StatusCode::UNAUTHORIZED.into_response(),
    };
    let Some(jwt) = verified.jwt else {
        return StatusCode::UNAUTHORIZED.into_response();
    };
    let thumbprint = verified.thumbprint;

    let request = match body {
        Some(Json(b)) => b,
        None => return StatusCode::BAD_REQUEST.into_response(),
    };

    let resource_token = request.resource_token.clone();
    let ctx = match state
        .config
        .verify_token_request(&jwt, &thumbprint, &resource_token, request)
        .await
    {
        Ok(c) => c,
        Err(_) => return StatusCode::UNAUTHORIZED.into_response(),
    };

    match state.service.exchange_token(ctx, &jwt).await {
        Ok(outcome) => AauthResponse(outcome).into_response(),
        Err(e) => InternalServiceError::from(e).into_response(),
    }
}

pub async fn pending_poll_handler<S, F, C>(
    State(state): State<PersonServerState<S, F, C>>,
    Path(id): Path<String>,
) -> Result<AauthResponse<AuthTokenPollOutcome>, InternalServiceError>
where
    S: PersonTokenService,
    F: MetadataFetcher,
    C: AccessServerClient,
{
    state
        .service
        .poll_pending(&id)
        .await
        .map(AauthResponse)
        .map_err(InternalServiceError::from)
}

pub async fn pending_post_handler<S, F, C>(
    State(state): State<PersonServerState<S, F, C>>,
    Path(id): Path<String>,
    PendingResumeInput(input): PendingResumeInput,
) -> Response
where
    S: PersonTokenService,
    F: MetadataFetcher,
    C: AccessServerClient,
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

pub async fn interaction_start_handler<S, F, C>(
    State(state): State<PersonServerState<S, F, C>>,
    Query(query): Query<InteractionStartQuery>,
) -> Response
where
    S: PersonTokenService,
    F: MetadataFetcher,
    C: AccessServerClient,
{
    match state.service.begin_interaction(&query.code).await {
        Ok(outcome) => AauthResponse(outcome).into_response(),
        Err(e) => InternalServiceError::from(e).into_response(),
    }
}

pub async fn interaction_callback_handler<S, F, C>(
    State(state): State<PersonServerState<S, F, C>>,
    Query(query): Query<InteractionCallbackQuery>,
) -> Response
where
    S: PersonTokenService,
    F: MetadataFetcher,
    C: AccessServerClient,
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
pub fn person_router<AppState, Svc, F, C>() -> Router<AppState>
where
    AppState: Clone + Send + Sync + 'static,
    Svc: PersonTokenService + 'static,
    F: MetadataFetcher + 'static,
    C: AccessServerClient + 'static,
    PersonServerState<Svc, F, C>: FromRef<AppState>,
{
    Router::new()
        .route(
            "/.well-known/aauth-person.json",
            get(person_metadata_handler::<Svc, F, C>),
        )
        .route("/auth/jwks", get(person_jwks_handler::<Svc, F, C>))
        .route("/aauth/token", post(token_exchange_handler::<Svc, F, C>))
        .route(
            "/pending/{id}",
            get(pending_poll_handler::<Svc, F, C>).post(pending_post_handler::<Svc, F, C>),
        )
        .route("/interact", get(interaction_start_handler::<Svc, F, C>))
        .route(
            "/interact/callback",
            get(interaction_callback_handler::<Svc, F, C>),
        )
}
