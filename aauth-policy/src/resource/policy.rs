use aauth::PendingInput;
use aauth::ResourceAccessContext;

use crate::PolicyError;
use crate::ResourceConsentDecision;

#[async_trait::async_trait]
pub trait ResourceConsentPolicy: Send + Sync + Clone {
    async fn evaluate(
        &self,
        ctx: &ResourceAccessContext,
    ) -> Result<ResourceConsentDecision, PolicyError>;

    async fn resume(
        &self,
        ctx: &ResourceAccessContext,
        input: PendingInput,
    ) -> Result<ResourceConsentDecision, PolicyError>;
}
