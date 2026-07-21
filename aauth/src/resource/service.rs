use crate::resource::access_context::ResourceAccessContext;
use crate::resource::outcome::{ResourceConsentFlowOutcome, ResourcePollOutcome};

#[derive(Clone)]
pub struct ResourceAccessConfig {
    pub interaction_url: String,
    pub pending_base_url: String,
    pub pending_path: String,
    pub pending_ttl_secs: u64,
}

#[async_trait::async_trait]
pub trait ResourceAccessService: Send + Sync + Clone {
    type Error: std::error::Error + Send + Sync + 'static;

    async fn consent_for_agent(
        &self,
        ctx: ResourceAccessContext,
    ) -> Result<ResourceConsentFlowOutcome, Self::Error>;

    async fn poll_pending(&self, pending_id: &str) -> Result<ResourcePollOutcome, Self::Error>;

    fn validate_opaque(&self, token: &str, agent_id: &str) -> bool;
}
