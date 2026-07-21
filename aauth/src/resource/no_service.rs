use crate::resource::access_context::ResourceAccessContext;
use crate::resource::outcome::{ResourceConsentFlowOutcome, ResourcePollOutcome};
use crate::resource::service::ResourceAccessService;

/// Marker service for [`super::ResourceAccessMode`] variants that do not use a
/// consent service (`IdentityBased`, `PsAsserted`).
#[derive(Clone, Copy, Debug, Default)]
pub struct NoResourceAccessService;

#[async_trait::async_trait]
impl ResourceAccessService for NoResourceAccessService {
    type Error = std::convert::Infallible;

    async fn consent_for_agent(
        &self,
        _ctx: ResourceAccessContext,
    ) -> Result<ResourceConsentFlowOutcome, Self::Error> {
        unreachable!("NoResourceAccessService is only for IdentityBased/PsAsserted modes")
    }

    async fn poll_pending(&self, _pending_id: &str) -> Result<ResourcePollOutcome, Self::Error> {
        unreachable!("NoResourceAccessService is only for IdentityBased/PsAsserted modes")
    }

    fn validate_opaque(&self, _token: &str, _agent_id: &str) -> bool {
        false
    }
}
