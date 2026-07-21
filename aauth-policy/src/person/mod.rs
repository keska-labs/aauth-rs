use aauth::AuthTokenPollOutcome;
use aauth::PendingInput;
use aauth::PersonTokenContext;
use aauth::PersonTokenService;
use aauth::interaction_code::canonicalize_code;
use aauth::person_server::config::PersonServerConfig;
use aauth::person_server::keys::PersonAuthJwtMinter;
use aauth::person_server::outcome::{PersonInteractionOutcome, PersonTokenFlowOutcome};
use aauth::protocol::PendingStatus;
use aauth::{PendingOutcome, PendingSnapshot};

use crate::PersonOrchestrationError;
use crate::PolicyError;
use crate::store::{PendingStore, PersonPendingContext, PersonPendingRecord, poll_auth_pending};

mod defer;
mod federation_pending;
mod interaction;
mod policy;

pub use policy::PersonTokenPolicy;

#[derive(Debug, thiserror::Error)]
pub enum PersonTokenServiceError<E>
where
    E: std::error::Error + Send + Sync + 'static,
{
    /// Store persistence failure. Not `#[from]` to avoid coherence conflicts when
    /// `E` could unify with `PolicyError` / `PersonOrchestrationError`.
    #[error(transparent)]
    PendingStore(E),
    #[error(transparent)]
    Policy(#[from] PolicyError),
    #[error(transparent)]
    Orchestration(#[from] PersonOrchestrationError),
}

#[derive(Clone)]
pub struct PolicyPersonTokenService<P, S, M> {
    pub policy: P,
    pub pending: S,
    pub minter: M,
    pub config: PersonServerConfig,
}

impl<P, S, M> PolicyPersonTokenService<P, S, M> {
    pub fn new(policy: P, pending: S, minter: M, config: PersonServerConfig) -> Self {
        Self {
            policy,
            pending,
            minter,
            config,
        }
    }
}

#[async_trait::async_trait]
impl<P, S, M> PersonTokenService for PolicyPersonTokenService<P, S, M>
where
    P: PersonTokenPolicy,
    S: PendingStore<PersonPendingRecord>,
    M: PersonAuthJwtMinter + Clone,
{
    type Error = PersonTokenServiceError<S::Error>;

    async fn exchange_token(
        &self,
        ctx: PersonTokenContext,
        agent_jwt: &str,
    ) -> Result<PersonTokenFlowOutcome, Self::Error> {
        if ctx.resource_claims.interaction.is_some() {
            return defer::create_resource_initiated_deferred_response(self, &ctx, agent_jwt).await;
        }
        let decision = self.policy.evaluate(&ctx).await?;
        defer::apply_person_decision(self, &ctx, decision, agent_jwt).await
    }

    async fn poll_pending(&self, pending_id: &str) -> Result<AuthTokenPollOutcome, Self::Error> {
        poll_auth_pending(&self.pending, pending_id)
            .await
            .map_err(PersonTokenServiceError::PendingStore)
    }

    async fn resume_pending(
        &self,
        pending_id: &str,
        input: PendingInput,
    ) -> Result<PersonTokenFlowOutcome, Self::Error> {
        let Some(record) = self.pending.load(pending_id).await.map_err(PersonTokenServiceError::PendingStore)? else {
            return Ok(PersonTokenFlowOutcome::Gone);
        };

        if record.is_expired() {
            let _ = self.pending.remove(pending_id).await;
            return Ok(PersonTokenFlowOutcome::Gone);
        }

        let PersonPendingContext {
            person_server_url,
            resource_url,
            agent_claims,
            resource_claims,
            exchange_request,
            agent_token,
            federation,
            ..
        } = record.context;

        if let Some(fed) = federation {
            return federation_pending::handle_federated_pending_post(
                self,
                pending_id,
                &fed,
                &agent_token,
                &self.config.resource_url,
                input,
            )
            .await;
        }

        let ctx = PersonTokenContext {
            person_server_url,
            resource_url,
            agent_claims,
            resource_claims,
            exchange_request,
        };

        let decision = self.policy.resume(&ctx, input).await?;
        defer::apply_person_pending_decision(self, &ctx, pending_id, decision, &agent_token).await
    }

    async fn begin_interaction(&self, code: &str) -> Result<PersonInteractionOutcome, Self::Error> {
        let canonical = canonicalize_code(code);
        let Some((pending_id, mut record)) = self
            .pending
            .find_if(|r| {
                r.context.ps_interaction_code.as_deref() == Some(canonical.as_str())
                    && !r.context.interaction_code_consumed
            })
            .await
            .map_err(PersonTokenServiceError::PendingStore)?
        else {
            return Ok(PersonInteractionOutcome::InvalidCode);
        };

        if record.is_expired() {
            let _ = self.pending.remove(&pending_id).await;
            return Ok(PersonInteractionOutcome::Expired);
        }

        record.context.interaction_code_consumed = true;
        if let PendingSnapshot::Waiting { status, .. } = &mut record.snapshot {
            *status = PendingStatus::Interacting;
        }
        self.pending.save(&pending_id, record.clone()).await.map_err(PersonTokenServiceError::PendingStore)?;

        if let Some(resource_ix) = record.context.resource_interaction.clone() {
            interaction::validate_interaction_url(&resource_ix.url)?;
            let callback_url = format!(
                "{}/callback?id={pending_id}",
                self.config.interaction_url.trim_end_matches('/')
            );
            let redirect =
                interaction::build_resource_interaction_redirect(&resource_ix, &callback_url)?;
            return Ok(PersonInteractionOutcome::Redirect(redirect));
        }

        let requirement = match &record.snapshot {
            PendingSnapshot::Waiting { requirement, .. } => requirement.clone(),
            _ => {
                return Ok(PersonInteractionOutcome::InvalidCode);
            }
        };
        let body =
            aauth::protocol::PendingBody::for_waiting(&requirement, PendingStatus::Interacting)
                .map_err(PersonOrchestrationError::PendingBody)?;
        Ok(PersonInteractionOutcome::Pending(body))
    }

    async fn resolve_interaction_callback(
        &self,
        pending_id: &str,
        callback_error: Option<&str>,
    ) -> Result<PersonTokenFlowOutcome, Self::Error> {
        let Some(record) = self.pending.load(pending_id).await.map_err(PersonTokenServiceError::PendingStore)? else {
            return Ok(PersonTokenFlowOutcome::Gone);
        };

        if record.is_expired() {
            let _ = self.pending.remove(pending_id).await;
            return Ok(PersonTokenFlowOutcome::Gone);
        }

        if let Some(err) = callback_error {
            let polling_err = interaction::map_interaction_callback_error(err);
            self.pending
                .complete(pending_id, PendingOutcome::Error(polling_err.clone()))
                .await
                .map_err(PersonTokenServiceError::PendingStore)?;
            return Ok(PersonTokenFlowOutcome::denied(polling_err));
        }

        let PersonPendingContext {
            person_server_url,
            resource_url,
            agent_claims,
            resource_claims,
            exchange_request,
            agent_token,
            federation,
            ..
        } = record.context;

        if federation.is_some() {
            return Ok(PersonTokenFlowOutcome::BadGateway);
        }

        let mut resource_claims = resource_claims;
        resource_claims.interaction = None;

        let ctx = PersonTokenContext {
            person_server_url,
            resource_url,
            agent_claims,
            resource_claims,
            exchange_request,
        };

        let decision = self.policy.evaluate(&ctx).await?;
        defer::apply_person_pending_decision(self, &ctx, pending_id, decision, &agent_token).await
    }
}
