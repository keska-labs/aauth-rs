use aauth::AccessTokenContext;
use aauth::PendingInput;

use crate::AccessTokenDecision;
use crate::PolicyError;

#[async_trait::async_trait]
pub trait AccessTokenPolicy: Send + Sync + Clone {
    async fn evaluate(&self, ctx: &AccessTokenContext) -> Result<AccessTokenDecision, PolicyError>;

    async fn resume(
        &self,
        ctx: &AccessTokenContext,
        input: PendingInput,
    ) -> Result<AccessTokenDecision, PolicyError>;
}
