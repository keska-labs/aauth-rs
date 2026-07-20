use axum::extract::{Path, State};

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
