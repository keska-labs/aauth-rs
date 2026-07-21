use axum::Json;
use axum::Router;
use axum::extract::{FromRef, OriginalUri, Path, State};
use axum::http::header::HOST;
use axum::http::{HeaderMap, StatusCode};
use axum::response::{IntoResponse, Response};
use axum::routing::{get, post};

use aauth::ResourceAccessContext;
use aauth::ResourceAccessService;
use aauth::ResourceConsentFlowOutcome;
use aauth::ResourcePollOutcome;
use aauth::jwt::ParsedToken;
use aauth::protocol::{AAUTH_ACCESS, AuthorizationGrantedResponse, AuthorizationRequest};
use aauth::signature::verify_request_signature;

use crate::{AauthResponse, InternalServiceError};

#[derive(Clone)]
pub struct ResourceServerState<S>
where
    S: ResourceAccessService,
{
    pub service: S,
    pub resource_url: String,
}

pub async fn resource_pending_poll_handler<S>(
    State(state): State<ResourceServerState<S>>,
    Path(id): Path<String>,
) -> Result<AauthResponse<ResourcePollOutcome>, InternalServiceError>
where
    S: ResourceAccessService,
{
    state
        .service
        .poll_pending(&id)
        .await
        .map(AauthResponse)
        .map_err(InternalServiceError::from)
}

/// Resource-managed `authorization_endpoint` (opaque / interaction; no resource token).
///
/// Spec: `draft-hardt-oauth-aauth-protocol.md#authorization-endpoint-request`,
/// `#authorization-endpoint-responses` (response without resource token).
pub async fn resource_authorize_handler<S>(
    State(state): State<ResourceServerState<S>>,
    OriginalUri(uri): OriginalUri,
    headers: HeaderMap,
    body: Option<Json<AuthorizationRequest>>,
) -> Response
where
    S: ResourceAccessService,
{
    let authority = headers
        .get(HOST)
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

    let agent = match ParsedToken::parse(&verified_sig.jwt) {
        Ok(ParsedToken::Agent(agent)) => agent,
        _ => return StatusCode::UNAUTHORIZED.into_response(),
    };

    let ctx = ResourceAccessContext {
        resource_url: state.resource_url.clone(),
        agent_claims: agent,
        scope: Some(request.scope.clone()),
    };

    match state.service.consent_for_agent(ctx).await {
        Ok(ResourceConsentFlowOutcome::GrantOpaque(token)) => {
            let mut headers = HeaderMap::new();
            headers.insert(AAUTH_ACCESS, token.parse().expect("token68 opaque"));
            (
                StatusCode::OK,
                headers,
                Json(AuthorizationGrantedResponse {
                    status: "authorized".into(),
                    scope: request.scope,
                }),
            )
                .into_response()
        }
        Ok(outcome) => AauthResponse(outcome).into_response(),
        Err(e) => InternalServiceError::from(e).into_response(),
    }
}

/// Canonical Resource Server routes.
///
/// Mounts:
/// - `GET /resource/pending/{id}`
/// - `POST /resource/authorize` (resource-managed opaque path)
///
/// Does not include [`crate::ResourceAuthLayer`]; apply that layer to protected
/// application routes separately. App state must implement [`FromRef`] to
/// [`ResourceServerState`].
pub fn resource_router<AppState, Svc>() -> Router<AppState>
where
    AppState: Clone + Send + Sync + 'static,
    Svc: ResourceAccessService + 'static,
    ResourceServerState<Svc>: FromRef<AppState>,
{
    Router::new()
        .route(
            "/resource/pending/{id}",
            get(resource_pending_poll_handler::<Svc>),
        )
        .route(
            "/resource/authorize",
            post(resource_authorize_handler::<Svc>),
        )
}
