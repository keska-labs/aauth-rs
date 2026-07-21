use aauth::DeferCreated;
use aauth::DeferRequirement;
use aauth::PendingOutcome;
use aauth::PendingSnapshot;
use aauth::ResourceAccessConfig;
use aauth::ResourceAccessContext;
use aauth::ResourceAccessService;
use aauth::ResourceConsentFlowOutcome;
use aauth::ResourcePollOutcome;
use aauth::generate_pending_id;
use aauth::pending_location;

use crate::PolicyError;
use crate::ResourceConsentDecision;
use crate::ResourceConsentPolicy;
use crate::store::{
    PendingStore, ResourcePendingContext, ResourcePendingRecord, poll_auth_pending,
};

use super::opaque::OpaqueAccessStore;

#[derive(Debug, thiserror::Error)]
pub enum ResourceAccessServiceError<E>
where
    E: std::error::Error + Send + Sync + 'static,
{
    /// Store persistence failure. Not `#[from]` to avoid coherence conflicts when
    /// `E` could unify with `PolicyError`.
    #[error(transparent)]
    PendingStore(E),
    #[error(transparent)]
    Policy(#[from] PolicyError),
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
    type Error = ResourceAccessServiceError<S::Error>;

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
        let outcome = poll_auth_pending(&self.pending, pending_id)
            .await
            .map_err(ResourceAccessServiceError::PendingStore)?;

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
) -> Result<ResourceConsentFlowOutcome, ResourceAccessServiceError<S::Error>>
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
            *code = aauth::generate_code();
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

    service.pending.create(record).await.map_err(ResourceAccessServiceError::PendingStore)?;

    Ok(ResourceConsentFlowOutcome::Deferred(DeferCreated {
        location,
        requirement: requirement.clone(),
    }))
}
