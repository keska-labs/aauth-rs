use axum::Json;
use axum::Router;
use axum::extract::{FromRef, OriginalUri, Path, State};
use axum::http::header::HOST;
use axum::http::{HeaderMap, StatusCode};
use axum::response::{IntoResponse, Response};
use axum::routing::{get, post};

use aauth::AccessServerConfig;
use aauth::AccessTokenContext;
use aauth::AuthTokenPollOutcome;
use aauth::access_server::service::AccessTokenService;
use aauth::metadata::MetadataFetcher;
use aauth::protocol::{AccessServerMetadata, AccessTokenExchangeRequest, JwksDocument};
use httpsig_key::{VerifyOptions, verify};

use crate::{AauthResponse, InternalServiceError, PendingResumeInput};

#[derive(Clone)]
pub struct AccessServerState<
    S: AccessTokenService,
    F: MetadataFetcher = aauth::StaticMetadataFetcher,
> {
    pub service: S,
    pub config: AccessServerConfig<F>,
}

#[cfg(feature = "policy")]
impl<P, S, M, F> AccessServerState<aauth_policy::PolicyAccessTokenService<P, S, M, F>, F>
where
    P: aauth_policy::AccessTokenPolicy,
    S: aauth_policy::PendingStore<aauth_policy::AccessPendingRecord>,
    M: aauth::access_server::keys::AccessAuthJwtMinter + Clone,
    F: MetadataFetcher + Clone + 'static,
{
    pub fn from_policy(policy: P, pending: S, minter: M, config: AccessServerConfig<F>) -> Self {
        Self {
            service: aauth_policy::PolicyAccessTokenService::new(
                policy,
                pending,
                minter,
                config.clone(),
            ),
            config,
        }
    }
}

pub async fn access_metadata_handler<S: AccessTokenService, F: MetadataFetcher>(
    State(state): State<AccessServerState<S, F>>,
) -> Json<AccessServerMetadata> {
    Json(AccessServerMetadata {
        issuer: Some(state.config.access_server_url.clone()),
        token_endpoint: format!("{}/access/aauth/token", state.config.access_server_url),
        jwks_uri: Some(state.config.access_jwks_uri.clone()),
        ..Default::default()
    })
}

pub async fn access_jwks_handler<S: AccessTokenService, F: MetadataFetcher>(
    State(state): State<AccessServerState<S, F>>,
) -> Json<JwksDocument> {
    Json(JwksDocument {
        keys: state.config.keys.access_server.jwk_set(),
    })
}

pub async fn access_token_exchange_handler<S: AccessTokenService, F: MetadataFetcher>(
    State(state): State<AccessServerState<S, F>>,
    OriginalUri(uri): OriginalUri,
    headers: HeaderMap,
    body: Option<Json<AccessTokenExchangeRequest>>,
) -> Response {
    let authority = headers
        .get(HOST)
        .and_then(|h| h.to_str().ok())
        .unwrap_or("localhost")
        .to_string();

    let request = match body {
        Some(Json(b)) => b,
        None => return StatusCode::BAD_REQUEST.into_response(),
    };

    if verify(
        "POST",
        &authority,
        uri.path(),
        &headers,
        &VerifyOptions::default(),
    )
    .is_err()
    {
        return StatusCode::UNAUTHORIZED.into_response();
    }

    let ctx = match AccessTokenContext::from_exchange(&state.config, &request) {
        Ok(c) => c,
        Err(_) => return StatusCode::BAD_REQUEST.into_response(),
    };

    match state.service.exchange_token(ctx).await {
        Ok(outcome) => AauthResponse(outcome).into_response(),
        Err(e) => InternalServiceError::from(e).into_response(),
    }
}

pub async fn access_pending_poll_handler<S: AccessTokenService, F: MetadataFetcher>(
    State(state): State<AccessServerState<S, F>>,
    Path(id): Path<String>,
) -> Result<AauthResponse<AuthTokenPollOutcome>, InternalServiceError> {
    state
        .service
        .poll_pending(&id)
        .await
        .map(AauthResponse)
        .map_err(InternalServiceError::from)
}

pub async fn access_pending_post_handler<S: AccessTokenService, F: MetadataFetcher>(
    State(state): State<AccessServerState<S, F>>,
    Path(id): Path<String>,
    PendingResumeInput(input): PendingResumeInput,
) -> Response {
    match state.service.resume_pending(&id, input).await {
        Ok(outcome) => AauthResponse(outcome).into_response(),
        Err(e) => InternalServiceError::from(e).into_response(),
    }
}

/// Canonical Access Server routes (relative to the Access Server base URL).
///
/// Mounts:
/// - `GET /.well-known/aauth-access.json`
/// - `GET /access/jwks`
/// - `POST /access/aauth/token`
/// - `GET|POST /access/pending/{id}`
///
/// Nest under the Access Server URL path (for example `.nest("/as", access_router())`)
/// when the AS shares an origin with other roles. App state must implement [`FromRef`]
/// to [`AccessServerState`].
pub fn access_router<AppState, Svc, F>() -> Router<AppState>
where
    AppState: Clone + Send + Sync + 'static,
    Svc: AccessTokenService + 'static,
    F: MetadataFetcher + 'static,
    AccessServerState<Svc, F>: FromRef<AppState>,
{
    Router::new()
        .route(
            "/.well-known/aauth-access.json",
            get(access_metadata_handler::<Svc, F>),
        )
        .route("/access/jwks", get(access_jwks_handler::<Svc, F>))
        .route(
            "/access/aauth/token",
            post(access_token_exchange_handler::<Svc, F>),
        )
        .route(
            "/access/pending/{id}",
            get(access_pending_poll_handler::<Svc, F>).post(access_pending_post_handler::<Svc, F>),
        )
}
