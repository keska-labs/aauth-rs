use axum::extract::{Path, State};

use crate::resource::ResourcePollOutcome;
use crate::resource::service::ResourceAccessService;
use crate::server_axum::InternalServiceError;

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
) -> Result<ResourcePollOutcome, InternalServiceError>
where
    S: ResourceAccessService,
{
    state
        .service
        .poll_pending(&id)
        .await
        .map_err(InternalServiceError::from)
}
