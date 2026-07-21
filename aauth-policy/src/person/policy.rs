use aauth::PendingInput;
use aauth::PersonTokenContext;

use crate::PersonTokenDecision;
use crate::PolicyError;

#[trait_variant::make(PersonTokenPolicy: Send)]
#[dynosaur::dynosaur(pub DynPersonTokenPolicy = dyn(box) PersonTokenPolicy, bridge(dyn))]
pub trait LocalPersonTokenPolicy: Sync {
    async fn evaluate(&self, ctx: &PersonTokenContext) -> Result<PersonTokenDecision, PolicyError>;

    async fn resume(
        &self,
        ctx: &PersonTokenContext,
        input: PendingInput,
    ) -> Result<PersonTokenDecision, PolicyError>;
}
