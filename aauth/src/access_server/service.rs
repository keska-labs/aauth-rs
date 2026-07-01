use crate::access_server::axum::AccessServerConfig;
use crate::access_server::keys::AccessAuthJwtMinter;
use crate::access_server::outcome::{AuthTokenFlowOutcome, AuthTokenPollOutcome};
use crate::deferred::{
    AccessPendingContext, AccessPendingRecord, DeferCreated, DeferRequirement, PendingInput,
    PendingOutcome, PendingSnapshot, PendingStore, generate_pending_id, pending_location,
};
use crate::error::AAuthError;
use crate::jwt::{VerifiedToken, decode_resource_token_unverified};
use crate::policy::{
    AccessTokenContext, AccessTokenPolicy, AuthGrant, PolicyError, TokenPolicyDecision,
};
use crate::protocol::TokenResponseBody;
use crate::server_axum::poll_outcome_from_snapshot;

#[derive(Debug, thiserror::Error)]
pub enum AccessTokenServiceError {
    #[error("pending store: {0}")]
    PendingStore(String),
    #[error("policy: {0}")]
    Policy(#[from] PolicyError),
    #[error("orchestration: {0}")]
    Orchestration(#[from] AAuthError),
}

#[async_trait::async_trait]
pub trait AccessTokenService: Send + Sync + Clone {
    type Error: std::error::Error + Send + Sync + 'static;

    async fn exchange_token(
        &self,
        ctx: AccessTokenContext,
    ) -> Result<AuthTokenFlowOutcome, Self::Error>;

    async fn poll_pending(&self, pending_id: &str) -> Result<AuthTokenPollOutcome, Self::Error>;

    async fn resume_pending(
        &self,
        pending_id: &str,
        input: PendingInput,
    ) -> Result<AuthTokenFlowOutcome, Self::Error>;
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
    type Error = AccessTokenServiceError;

    async fn exchange_token(
        &self,
        ctx: AccessTokenContext,
    ) -> Result<AuthTokenFlowOutcome, Self::Error> {
        let decision = self.policy.evaluate(&ctx).await?;
        apply_access_decision(self, &ctx, decision).await
    }

    async fn poll_pending(&self, pending_id: &str) -> Result<AuthTokenPollOutcome, Self::Error> {
        let Some(record) = self
            .pending
            .load(pending_id)
            .await
            .map_err(|e| AccessTokenServiceError::PendingStore(e.to_string()))?
        else {
            return Ok(AuthTokenPollOutcome::Gone);
        };

        if record.is_expired() {
            let _ = self.pending.remove(pending_id).await;
            return Ok(AuthTokenPollOutcome::Gone);
        }

        Ok(poll_outcome_from_snapshot(&record.snapshot))
    }

    async fn resume_pending(
        &self,
        pending_id: &str,
        input: PendingInput,
    ) -> Result<AuthTokenFlowOutcome, Self::Error> {
        let Some(record) = self
            .pending
            .load(pending_id)
            .await
            .map_err(|e| AccessTokenServiceError::PendingStore(e.to_string()))?
        else {
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

pub fn build_access_context(
    config: &AccessServerConfig,
    request: &crate::protocol::AccessTokenExchangeRequest,
) -> Result<AccessTokenContext, AAuthError> {
    let agent = match VerifiedToken::decode_unverified(&request.agent_token)? {
        VerifiedToken::Agent(c) => c,
        _ => {
            return Err(AAuthError::Message(
                "agent_token must be an agent JWT".into(),
            ));
        }
    };
    let resource_claims = decode_resource_token_unverified(&request.resource_token)?;

    Ok(AccessTokenContext {
        access_server_url: config.access_server_url.clone(),
        resource_url: config.resource_url.clone(),
        person_server_url: config.person_server_url.clone(),
        agent_claims: agent,
        resource_claims,
        resource_token: request.resource_token.clone(),
        agent_token: request.agent_token.clone(),
    })
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
    decision: TokenPolicyDecision,
) -> Result<AuthTokenFlowOutcome, AccessTokenServiceError>
where
    P: AccessTokenPolicy,
    S: PendingStore<AccessPendingRecord>,
    M: AccessAuthJwtMinter + Clone,
{
    match decision {
        TokenPolicyDecision::Grant(grant) => {
            let body = mint_access_auth(&service.minter, &service.config, grant, ctx);
            Ok(AuthTokenFlowOutcome::granted(body))
        }
        TokenPolicyDecision::Deny(err) => Ok(AuthTokenFlowOutcome::denied(err)),
        TokenPolicyDecision::Defer(requirement) => {
            create_deferred_access_response(service, ctx, requirement).await
        }
    }
}

async fn apply_access_pending_decision<P, S, M>(
    service: &PolicyAccessTokenService<P, S, M>,
    ctx: &AccessTokenContext,
    pending_id: &str,
    decision: TokenPolicyDecision,
) -> Result<AuthTokenFlowOutcome, AccessTokenServiceError>
where
    P: AccessTokenPolicy,
    S: PendingStore<AccessPendingRecord>,
    M: AccessAuthJwtMinter + Clone,
{
    match decision {
        TokenPolicyDecision::Grant(grant) => {
            let body = mint_access_auth(&service.minter, &service.config, grant, ctx);
            service
                .pending
                .complete(pending_id, PendingOutcome::AuthToken(body.clone()))
                .await
                .map_err(|e| AccessTokenServiceError::PendingStore(e.to_string()))?;
            Ok(AuthTokenFlowOutcome::granted(body))
        }
        TokenPolicyDecision::Deny(err) => {
            service
                .pending
                .complete(pending_id, PendingOutcome::Error(err.clone()))
                .await
                .map_err(|e| AccessTokenServiceError::PendingStore(e.to_string()))?;
            Ok(AuthTokenFlowOutcome::denied(err))
        }
        TokenPolicyDecision::Defer(requirement) => {
            update_access_pending_defer(service, pending_id, requirement).await
        }
    }
}

async fn update_access_pending_defer<P, S, M>(
    service: &PolicyAccessTokenService<P, S, M>,
    pending_id: &str,
    requirement: DeferRequirement,
) -> Result<AuthTokenFlowOutcome, AccessTokenServiceError>
where
    P: AccessTokenPolicy,
    S: PendingStore<AccessPendingRecord>,
    M: AccessAuthJwtMinter + Clone,
{
    let Some(mut record) = service
        .pending
        .load(pending_id)
        .await
        .map_err(|e| AccessTokenServiceError::PendingStore(e.to_string()))?
    else {
        return Ok(AuthTokenFlowOutcome::Gone);
    };
    record.snapshot = PendingSnapshot::waiting(requirement.clone());
    service
        .pending
        .save(pending_id, record)
        .await
        .map_err(|e| AccessTokenServiceError::PendingStore(e.to_string()))?;

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
) -> Result<AuthTokenFlowOutcome, AccessTokenServiceError>
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

    service
        .pending
        .create(record)
        .await
        .map_err(|e| AccessTokenServiceError::PendingStore(e.to_string()))?;

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
