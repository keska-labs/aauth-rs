use aauth::PendingInput;
use aauth::PersonTokenContext;

use crate::PersonTokenDecision;
use crate::PolicyError;

#[async_trait::async_trait]
pub trait PersonTokenPolicy: Send + Sync + Clone {
    async fn evaluate(&self, ctx: &PersonTokenContext) -> Result<PersonTokenDecision, PolicyError>;

    async fn resume(
        &self,
        ctx: &PersonTokenContext,
        input: PendingInput,
    ) -> Result<PersonTokenDecision, PolicyError>;
}
