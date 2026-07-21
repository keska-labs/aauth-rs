use crate::deferred::AuthTokenPollOutcome;
use crate::deferred::PendingInput;
use crate::person_server::outcome::{PersonInteractionOutcome, PersonTokenFlowOutcome};
use crate::person_server::token_context::PersonTokenContext;

#[async_trait::async_trait]
pub trait PersonTokenService: Send + Sync + Clone {
    type Error: std::error::Error + Send + Sync + 'static;

    async fn exchange_token(
        &self,
        ctx: PersonTokenContext,
        agent_jwt: &str,
    ) -> Result<PersonTokenFlowOutcome, Self::Error>;

    async fn poll_pending(&self, pending_id: &str) -> Result<AuthTokenPollOutcome, Self::Error>;

    async fn resume_pending(
        &self,
        pending_id: &str,
        input: PendingInput,
    ) -> Result<PersonTokenFlowOutcome, Self::Error>;

    async fn begin_interaction(&self, code: &str) -> Result<PersonInteractionOutcome, Self::Error>;

    async fn resolve_interaction_callback(
        &self,
        pending_id: &str,
        callback_error: Option<&str>,
    ) -> Result<PersonTokenFlowOutcome, Self::Error>;
}
