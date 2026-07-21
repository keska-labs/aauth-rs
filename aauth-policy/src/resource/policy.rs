use aauth::PendingInput;
use aauth::ResourceAccessContext;

use crate::PolicyError;
use crate::ResourceConsentDecision;

#[trait_variant::make(ResourceConsentPolicy: Send)]
#[dynosaur::dynosaur(pub DynResourceConsentPolicy = dyn(box) ResourceConsentPolicy, bridge(dyn))]
pub trait LocalResourceConsentPolicy: Sync {
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
