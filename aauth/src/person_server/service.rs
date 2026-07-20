use crate::deferred::AuthTokenPollOutcome;
use crate::deferred::poll_auth_pending;
use crate::deferred::{
    PendingInput, PendingOutcome, PendingSnapshot, PendingStore, PersonPendingContext,
    PersonPendingRecord,
};
use crate::error::AAuthError;
use crate::interaction_code::canonicalize_code;
use crate::person_server::config::PersonServerConfig;
use crate::person_server::keys::PersonAuthJwtMinter;
use crate::person_server::outcome::{PersonInteractionOutcome, PersonTokenFlowOutcome};
use crate::policy::{PersonTokenContext, PersonTokenPolicy, PolicyError};
use crate::protocol::PendingStatus;

use super::defer::{
    apply_person_decision, apply_person_pending_decision,
    create_resource_initiated_deferred_response,
};
use super::federation_pending::handle_federated_pending_post;
use super::interaction::{
    build_resource_interaction_redirect, map_interaction_callback_error, validate_interaction_url,
};

#[derive(Debug, thiserror::Error)]
pub enum PersonTokenServiceError {
    #[error("pending store: {0}")]
    PendingStore(String),
    #[error("policy: {0}")]
    Policy(#[from] PolicyError),
    #[error("orchestration: {0}")]
    Orchestration(#[from] AAuthError),
}

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
    type Error = PersonTokenServiceError;

    async fn exchange_token(
        &self,
        ctx: PersonTokenContext,
        agent_jwt: &str,
    ) -> Result<PersonTokenFlowOutcome, Self::Error> {
        if ctx.resource_claims.interaction.is_some() {
            return create_resource_initiated_deferred_response(self, &ctx, agent_jwt).await;
        }
        let decision = self.policy.evaluate(&ctx).await?;
        apply_person_decision(self, &ctx, decision, agent_jwt).await
    }

    async fn poll_pending(&self, pending_id: &str) -> Result<AuthTokenPollOutcome, Self::Error> {
        poll_auth_pending(&self.pending, pending_id)
            .await
            .map_err(|e| PersonTokenServiceError::PendingStore(e.to_string()))
    }

    async fn resume_pending(
        &self,
        pending_id: &str,
        input: PendingInput,
    ) -> Result<PersonTokenFlowOutcome, Self::Error> {
        let Some(record) = self
            .pending
            .load(pending_id)
            .await
            .map_err(|e| PersonTokenServiceError::PendingStore(e.to_string()))?
        else {
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
            return handle_federated_pending_post(
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
        apply_person_pending_decision(self, &ctx, pending_id, decision, &agent_token).await
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
            .map_err(|e| PersonTokenServiceError::PendingStore(e.to_string()))?
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
        self.pending
            .save(&pending_id, record.clone())
            .await
            .map_err(|e| PersonTokenServiceError::PendingStore(e.to_string()))?;

        if let Some(resource_ix) = record.context.resource_interaction.clone() {
            validate_interaction_url(&resource_ix.url)?;
            let callback_url = format!(
                "{}/callback?id={pending_id}",
                self.config.interaction_url.trim_end_matches('/')
            );
            let redirect = build_resource_interaction_redirect(&resource_ix, &callback_url)?;
            return Ok(PersonInteractionOutcome::Redirect(redirect));
        }

        let requirement = match &record.snapshot {
            PendingSnapshot::Waiting { requirement, .. } => requirement.clone(),
            _ => {
                return Ok(PersonInteractionOutcome::InvalidCode);
            }
        };
        let body =
            crate::protocol::PendingBody::for_waiting(&requirement, PendingStatus::Interacting)
                .map_err(PersonTokenServiceError::Orchestration)?;
        Ok(PersonInteractionOutcome::Pending(body))
    }

    async fn resolve_interaction_callback(
        &self,
        pending_id: &str,
        callback_error: Option<&str>,
    ) -> Result<PersonTokenFlowOutcome, Self::Error> {
        let Some(record) = self
            .pending
            .load(pending_id)
            .await
            .map_err(|e| PersonTokenServiceError::PendingStore(e.to_string()))?
        else {
            return Ok(PersonTokenFlowOutcome::Gone);
        };

        if record.is_expired() {
            let _ = self.pending.remove(pending_id).await;
            return Ok(PersonTokenFlowOutcome::Gone);
        }

        if let Some(err) = callback_error {
            let polling_err = map_interaction_callback_error(err);
            self.pending
                .complete(pending_id, PendingOutcome::Error(polling_err.clone()))
                .await
                .map_err(|e| PersonTokenServiceError::PendingStore(e.to_string()))?;
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
        apply_person_pending_decision(self, &ctx, pending_id, decision, &agent_token).await
    }
}
