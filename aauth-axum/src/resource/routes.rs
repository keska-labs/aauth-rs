use axum::Router;
use axum::extract::{FromRef, Path, State};
use axum::routing::get;

use aauth::ResourceAccessService;
use aauth::ResourcePollOutcome;

use crate::{AauthResponse, InternalServiceError};

#[derive(Clone)]
pub struct ResourceServerState<S>
where
    S: ResourceAccessService,
{
    pub service: S,
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

/// Canonical Resource Server routes.
///
/// Mounts:
/// - `GET /resource/pending/{id}`
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
    Router::new().route(
        "/resource/pending/{id}",
        get(resource_pending_poll_handler::<Svc>),
    )
}
