use crate::deferred::{
    DeferCreated, DeferRequirement, PendingOutcome, PendingSnapshot, PendingStore,
    ResourcePendingContext, ResourcePendingRecord, generate_pending_id, pending_location,
};
use crate::error::AAuthError;
use crate::policy::{
    PolicyError, ResourceAccessContext, ResourceConsentDecision, ResourceConsentPolicy,
};
use crate::resource::opaque::OpaqueAccessStore;
use crate::resource::outcome::{ResourceConsentFlowOutcome, ResourcePollOutcome};
use crate::server_axum::resource_poll_outcome_from_snapshot;

#[derive(Clone)]
pub struct ResourceAccessConfig {
    pub interaction_url: String,
    pub pending_base_url: String,
    pub pending_path: String,
    pub pending_ttl_secs: u64,
}

#[derive(Debug, thiserror::Error)]
pub enum ResourceAccessServiceError {
    #[error("pending store: {0}")]
    PendingStore(String),
    #[error("policy: {0}")]
    Policy(#[from] PolicyError),
    #[error("orchestration: {0}")]
    Orchestration(#[from] AAuthError),
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

#[derive(Clone)]
pub struct PolicyResourceAccessService<P, S, O> {
    pub policy: P,
    pub pending: S,
    pub opaque: O,
    pub config: ResourceAccessConfig,
}

impl<P, S, O> PolicyResourceAccessService<P, S, O> {
    pub fn new(policy: P, pending: S, opaque: O, config: ResourceAccessConfig) -> Self {
        Self {
            policy,
            pending,
            opaque,
            config,
        }
    }
}

#[async_trait::async_trait]
impl<P, S, O> ResourceAccessService for PolicyResourceAccessService<P, S, O>
where
    P: ResourceConsentPolicy,
    S: PendingStore<ResourcePendingRecord>,
    O: OpaqueAccessStore + Clone,
{
    type Error = ResourceAccessServiceError;

    async fn consent_for_agent(
        &self,
        ctx: ResourceAccessContext,
    ) -> Result<ResourceConsentFlowOutcome, Self::Error> {
        let decision = self.policy.evaluate(&ctx).await?;
        match decision {
            ResourceConsentDecision::GrantOpaque => Ok(ResourceConsentFlowOutcome::GrantOpaque(
                self.opaque.issue(ctx.agent_claims.identifier()),
            )),
            ResourceConsentDecision::Deny(err) => Ok(ResourceConsentFlowOutcome::Denied(err)),
            ResourceConsentDecision::Defer(mut requirement) => {
                create_deferred_resource_response(self, &ctx, &mut requirement).await
            }
        }
    }

    async fn poll_pending(&self, pending_id: &str) -> Result<ResourcePollOutcome, Self::Error> {
        let Some(record) = self
            .pending
            .load(pending_id)
            .await
            .map_err(|e| ResourceAccessServiceError::PendingStore(e.to_string()))?
        else {
            return Ok(ResourcePollOutcome::Gone);
        };

        if record.is_expired() {
            let _ = self.pending.remove(pending_id).await;
            return Ok(ResourcePollOutcome::Gone);
        }

        let outcome = resource_poll_outcome_from_snapshot(&record.snapshot);

        if matches!(
            &outcome,
            ResourcePollOutcome::Complete(PendingOutcome::OpaqueAccess(_))
                | ResourcePollOutcome::Complete(PendingOutcome::AuthToken(_))
        ) {
            let _ = self.pending.remove(pending_id).await;
        }

        Ok(outcome)
    }

    fn validate_opaque(&self, token: &str, agent_id: &str) -> bool {
        self.opaque.validate(token, agent_id)
    }
}

async fn create_deferred_resource_response<P, S, O>(
    service: &PolicyResourceAccessService<P, S, O>,
    ctx: &ResourceAccessContext,
    requirement: &mut DeferRequirement,
) -> Result<ResourceConsentFlowOutcome, ResourceAccessServiceError>
where
    P: ResourceConsentPolicy,
    S: PendingStore<ResourcePendingRecord>,
    O: OpaqueAccessStore + Clone,
{
    if let DeferRequirement::Interaction { url, code } = requirement {
        if url.is_empty() {
            *url = service.config.interaction_url.clone();
        }
        if code.is_empty() {
            *code = crate::interaction_code::generate_code();
        }
    }

    let id = generate_pending_id();
    let location = pending_location(
        &service.config.pending_base_url,
        &service.config.pending_path,
        &id,
    );
    let record = ResourcePendingRecord::new(
        id,
        ResourcePendingContext {
            resource_url: ctx.resource_url.clone(),
            agent_claims: ctx.agent_claims.clone(),
            scope: ctx.scope.clone(),
        },
        PendingSnapshot::waiting(requirement.clone()),
        service.config.pending_ttl_secs,
    );

    service
        .pending
        .create(record)
        .await
        .map_err(|e| ResourceAccessServiceError::PendingStore(e.to_string()))?;

    Ok(ResourceConsentFlowOutcome::Deferred(DeferCreated {
        location,
        requirement: requirement.clone(),
    }))
}
