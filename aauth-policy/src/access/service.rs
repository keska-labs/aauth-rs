use aauth::AccessTokenContext;
use aauth::AccessTokenService;
use aauth::AuthTokenFlowOutcome;
use aauth::AuthTokenPollOutcome;
use aauth::DeferCreated;
use aauth::DeferRequirement;
use aauth::PendingInput;
use aauth::PendingOutcome;
use aauth::PendingSnapshot;
use aauth::access_server::config::AccessServerConfig;
use aauth::access_server::keys::AccessAuthJwtMinter;
use aauth::generate_pending_id;
use aauth::pending_location;
use aauth::protocol::TokenResponseBody;

use crate::AccessTokenDecision;
use crate::AccessTokenPolicy;
use crate::AuthGrant;
use crate::PolicyError;
use crate::store::{AccessPendingContext, AccessPendingRecord, PendingStore, poll_auth_pending};

#[derive(Debug, thiserror::Error)]
pub enum AccessTokenServiceError<E>
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
pub struct PolicyAccessTokenService<P, S, M> {
    pub policy: P,
    pub pending: S,
    pub minter: M,
    pub config: AccessServerConfig,
}

impl<P, S, M> PolicyAccessTokenService<P, S, M> {
    pub fn new(policy: P, pending: S, minter: M, config: AccessServerConfig) -> Self {
        Self {
            policy,
            pending,
            minter,
            config,
        }
    }
}

#[async_trait::async_trait]
impl<P, S, M> AccessTokenService for PolicyAccessTokenService<P, S, M>
where
    P: AccessTokenPolicy,
    S: PendingStore<AccessPendingRecord>,
    M: AccessAuthJwtMinter + Clone,
{
    type Error = AccessTokenServiceError<S::Error>;

    async fn exchange_token(
        &self,
        ctx: AccessTokenContext,
    ) -> Result<AuthTokenFlowOutcome, Self::Error> {
        let decision = self.policy.evaluate(&ctx).await?;
        apply_access_decision(self, &ctx, decision).await
    }

    async fn poll_pending(&self, pending_id: &str) -> Result<AuthTokenPollOutcome, Self::Error> {
        poll_auth_pending(&self.pending, pending_id)
            .await
            .map_err(AccessTokenServiceError::PendingStore)
    }

    async fn resume_pending(
        &self,
        pending_id: &str,
        input: PendingInput,
    ) -> Result<AuthTokenFlowOutcome, Self::Error> {
        let Some(record) = self.pending.load(pending_id).await.map_err(AccessTokenServiceError::PendingStore)? else {
            return Ok(AuthTokenFlowOutcome::Gone);
        };

        if record.is_expired() {
            let _ = self.pending.remove(pending_id).await;
            return Ok(AuthTokenFlowOutcome::Gone);
        }

        let ctx = access_context_from_pending(record.context);
        let decision = self.policy.resume(&ctx, input).await?;
        apply_access_pending_decision(self, &ctx, pending_id, decision).await
    }
}

fn access_context_from_pending(c: AccessPendingContext) -> AccessTokenContext {
    AccessTokenContext {
        access_server_url: c.access_server_url,
        resource_url: c.resource_url,
        person_server_url: c.person_server_url,
        agent_claims: c.agent_claims,
        resource_claims: c.resource_claims,
        resource_token: c.resource_token,
        agent_token: c.agent_token,
    }
}

async fn apply_access_decision<P, S, M>(
    service: &PolicyAccessTokenService<P, S, M>,
    ctx: &AccessTokenContext,
    decision: AccessTokenDecision,
) -> Result<AuthTokenFlowOutcome, AccessTokenServiceError<S::Error>>
where
    P: AccessTokenPolicy,
    S: PendingStore<AccessPendingRecord>,
    M: AccessAuthJwtMinter + Clone,
{
    match decision {
        AccessTokenDecision::Grant(grant) => {
            let body = mint_access_auth(&service.minter, &service.config, grant, ctx);
            Ok(AuthTokenFlowOutcome::granted(body))
        }
        AccessTokenDecision::Deny(err) => Ok(AuthTokenFlowOutcome::denied(err)),
        AccessTokenDecision::Defer(requirement) => {
            create_deferred_access_response(service, ctx, requirement).await
        }
    }
}

async fn apply_access_pending_decision<P, S, M>(
    service: &PolicyAccessTokenService<P, S, M>,
    ctx: &AccessTokenContext,
    pending_id: &str,
    decision: AccessTokenDecision,
) -> Result<AuthTokenFlowOutcome, AccessTokenServiceError<S::Error>>
where
    P: AccessTokenPolicy,
    S: PendingStore<AccessPendingRecord>,
    M: AccessAuthJwtMinter + Clone,
{
    match decision {
        AccessTokenDecision::Grant(grant) => {
            let body = mint_access_auth(&service.minter, &service.config, grant, ctx);
            service
                .pending
                .complete(pending_id, PendingOutcome::AuthToken(body.clone()))
                .await
                .map_err(AccessTokenServiceError::PendingStore)?;
            Ok(AuthTokenFlowOutcome::granted(body))
        }
        AccessTokenDecision::Deny(err) => {
            service
                .pending
                .complete(pending_id, PendingOutcome::Error(err.clone()))
                .await
                .map_err(AccessTokenServiceError::PendingStore)?;
            Ok(AuthTokenFlowOutcome::denied(err))
        }
        AccessTokenDecision::Defer(requirement) => {
            update_access_pending_defer(service, pending_id, requirement).await
        }
    }
}

async fn update_access_pending_defer<P, S, M>(
    service: &PolicyAccessTokenService<P, S, M>,
    pending_id: &str,
    requirement: DeferRequirement,
) -> Result<AuthTokenFlowOutcome, AccessTokenServiceError<S::Error>>
where
    P: AccessTokenPolicy,
    S: PendingStore<AccessPendingRecord>,
    M: AccessAuthJwtMinter + Clone,
{
    let Some(mut record) = service.pending.load(pending_id).await.map_err(AccessTokenServiceError::PendingStore)? else {
        return Ok(AuthTokenFlowOutcome::Gone);
    };
    record.snapshot = PendingSnapshot::waiting(requirement.clone());
    service.pending.save(pending_id, record).await.map_err(AccessTokenServiceError::PendingStore)?;

    let location = pending_location(
        &service.config.pending_base_url,
        &service.config.pending_path,
        pending_id,
    );
    Ok(AuthTokenFlowOutcome::deferred(DeferCreated {
        location,
        requirement,
    }))
}

async fn create_deferred_access_response<P, S, M>(
    service: &PolicyAccessTokenService<P, S, M>,
    ctx: &AccessTokenContext,
    requirement: DeferRequirement,
) -> Result<AuthTokenFlowOutcome, AccessTokenServiceError<S::Error>>
where
    P: AccessTokenPolicy,
    S: PendingStore<AccessPendingRecord>,
    M: AccessAuthJwtMinter + Clone,
{
    let id = generate_pending_id();
    let location = pending_location(
        &service.config.pending_base_url,
        &service.config.pending_path,
        &id,
    );
    let record = AccessPendingRecord::new(
        id,
        AccessPendingContext {
            access_server_url: ctx.access_server_url.clone(),
            resource_url: ctx.resource_url.clone(),
            person_server_url: ctx.person_server_url.clone(),
            agent_claims: ctx.agent_claims.clone(),
            resource_claims: ctx.resource_claims.clone(),
            resource_token: ctx.resource_token.clone(),
            agent_token: ctx.agent_token.clone(),
        },
        PendingSnapshot::waiting(requirement.clone()),
        service.config.pending_ttl_secs,
    );

    service.pending.create(record).await.map_err(AccessTokenServiceError::PendingStore)?;

    Ok(AuthTokenFlowOutcome::deferred(DeferCreated {
        location,
        requirement,
    }))
}

fn mint_access_auth<M: AccessAuthJwtMinter>(
    minter: &M,
    config: &AccessServerConfig,
    grant: AuthGrant,
    ctx: &AccessTokenContext,
) -> TokenResponseBody {
    let auth_jwt = minter.mint_access_auth_jwt(
        &config.access_server_url,
        &config.resource_url,
        ctx.agent_claims.identifier(),
        Some(&grant.sub),
        grant
            .scope
            .as_deref()
            .or(ctx.resource_claims.scope.as_deref()),
    );
    TokenResponseBody {
        auth_token: auth_jwt,
        expires_in: 3600,
    }
}
