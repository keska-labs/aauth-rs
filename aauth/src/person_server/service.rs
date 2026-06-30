use std::sync::Arc;

use crate::deferred::AuthTokenPollOutcome;
use crate::deferred::{
    DeferCreated, DeferRequirement, FederationPendingState, PendingInput, PendingOutcome,
    PendingSnapshot, PendingStore, PersonPendingContext, PersonPendingRecord, ServerPollOptions,
    ServerPollOutcome, generate_pending_id, pending_location, poll_pending_http,
    post_pending_input,
};
use crate::error::AAuthError;
use crate::person_server::axum::PersonServerConfig;
use crate::person_server::federation::{
    FederationOutcome, federate_to_access_server, verify_federated_auth_token,
};
use crate::person_server::keys::AuthJwtMinter;
use crate::person_server::orchestrate::{PersonOrchestrateConfig, mint_person_auth};
use crate::person_server::outcome::PersonTokenFlowOutcome;
use crate::policy::{PersonTokenContext, PersonTokenDecision, PersonTokenPolicy, PolicyError};
use crate::server_axum::poll_outcome_from_snapshot;
use crate::types::{AAuthErrorCode, AAuthProtocolError};

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

    fn orch(&self) -> PersonOrchestrateConfig {
        self.config.orchestrate()
    }
}

#[async_trait::async_trait]
impl<P, S, M> PersonTokenService for PolicyPersonTokenService<P, S, M>
where
    P: PersonTokenPolicy,
    S: PendingStore<PersonPendingRecord>,
    M: AuthJwtMinter + Clone,
{
    type Error = PersonTokenServiceError;

    async fn exchange_token(
        &self,
        ctx: PersonTokenContext,
        agent_jwt: &str,
    ) -> Result<PersonTokenFlowOutcome, Self::Error> {
        let decision = self.policy.evaluate(&ctx).await?;
        apply_person_decision(self, &ctx, decision, agent_jwt).await
    }

    async fn poll_pending(&self, pending_id: &str) -> Result<AuthTokenPollOutcome, Self::Error> {
        let Some(record) = self
            .pending
            .load(pending_id)
            .await
            .map_err(|e| PersonTokenServiceError::PendingStore(e.to_string()))?
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
}

async fn apply_person_decision<P, S, M>(
    service: &PolicyPersonTokenService<P, S, M>,
    ctx: &PersonTokenContext,
    decision: PersonTokenDecision,
    agent_jwt: &str,
) -> Result<PersonTokenFlowOutcome, PersonTokenServiceError>
where
    P: PersonTokenPolicy,
    S: PendingStore<PersonPendingRecord>,
    M: AuthJwtMinter + Clone,
{
    let orch = service.orch();
    match decision {
        PersonTokenDecision::Grant(grant) => {
            let body = mint_person_auth(
                &service.minter,
                &orch,
                &grant,
                ctx.agent_claims.identifier(),
            );
            Ok(PersonTokenFlowOutcome::granted(body))
        }
        PersonTokenDecision::Federate => match federate_to_access_server(
            &orch.http_client,
            &orch,
            &ctx.exchange_request.resource_token,
            agent_jwt,
        )
        .await
        {
            Ok(FederationOutcome::Complete(body)) => Ok(PersonTokenFlowOutcome::granted(body)),
            Ok(FederationOutcome::Deferred {
                requirement,
                as_pending_url,
                access_server_url,
            }) => {
                create_federated_deferred_response(
                    service,
                    ctx,
                    None,
                    requirement,
                    FederationPendingState {
                        access_server_url,
                        as_pending_url,
                    },
                    agent_jwt,
                )
                .await
            }
            Err(_) => Ok(PersonTokenFlowOutcome::Unauthorized),
        },
        PersonTokenDecision::Deny(err) => Ok(PersonTokenFlowOutcome::denied(err)),
        PersonTokenDecision::Defer(requirement) => {
            create_deferred_person_response(service, ctx, requirement, agent_jwt).await
        }
    }
}

async fn apply_person_pending_decision<P, S, M>(
    service: &PolicyPersonTokenService<P, S, M>,
    ctx: &PersonTokenContext,
    pending_id: &str,
    decision: PersonTokenDecision,
    agent_jwt: &str,
) -> Result<PersonTokenFlowOutcome, PersonTokenServiceError>
where
    P: PersonTokenPolicy,
    S: PendingStore<PersonPendingRecord>,
    M: AuthJwtMinter + Clone,
{
    let orch = service.orch();
    match decision {
        PersonTokenDecision::Grant(grant) => {
            let body = mint_person_auth(
                &service.minter,
                &orch,
                &grant,
                ctx.agent_claims.identifier(),
            );
            service
                .pending
                .complete(pending_id, PendingOutcome::AuthToken(body.clone()))
                .await
                .map_err(|e| PersonTokenServiceError::PendingStore(e.to_string()))?;
            Ok(PersonTokenFlowOutcome::granted(body))
        }
        PersonTokenDecision::Federate => match federate_to_access_server(
            &orch.http_client,
            &orch,
            &ctx.exchange_request.resource_token,
            agent_jwt,
        )
        .await
        {
            Ok(FederationOutcome::Complete(body)) => {
                service
                    .pending
                    .complete(pending_id, PendingOutcome::AuthToken(body.clone()))
                    .await
                    .map_err(|e| PersonTokenServiceError::PendingStore(e.to_string()))?;
                Ok(PersonTokenFlowOutcome::granted(body))
            }
            Ok(FederationOutcome::Deferred {
                requirement,
                as_pending_url,
                access_server_url,
            }) => {
                create_federated_deferred_response(
                    service,
                    ctx,
                    Some(pending_id),
                    requirement,
                    FederationPendingState {
                        access_server_url,
                        as_pending_url,
                    },
                    agent_jwt,
                )
                .await
            }
            Err(_) => Ok(PersonTokenFlowOutcome::Unauthorized),
        },
        PersonTokenDecision::Deny(err) => {
            service
                .pending
                .complete(pending_id, PendingOutcome::Error(err.clone()))
                .await
                .map_err(|e| PersonTokenServiceError::PendingStore(e.to_string()))?;
            Ok(PersonTokenFlowOutcome::denied(err))
        }
        PersonTokenDecision::Defer(requirement) => {
            update_person_pending_defer(service, pending_id, requirement).await
        }
    }
}

async fn update_person_pending_defer<P, S, M>(
    service: &PolicyPersonTokenService<P, S, M>,
    pending_id: &str,
    requirement: DeferRequirement,
) -> Result<PersonTokenFlowOutcome, PersonTokenServiceError>
where
    P: PersonTokenPolicy,
    S: PendingStore<PersonPendingRecord>,
    M: AuthJwtMinter + Clone,
{
    let orch = service.orch();
    let Some(mut record) = service
        .pending
        .load(pending_id)
        .await
        .map_err(|e| PersonTokenServiceError::PendingStore(e.to_string()))?
    else {
        return Ok(PersonTokenFlowOutcome::Gone);
    };
    record.snapshot = PendingSnapshot::waiting(requirement.clone());
    service
        .pending
        .save(pending_id, record)
        .await
        .map_err(|e| PersonTokenServiceError::PendingStore(e.to_string()))?;

    let location = pending_location(&orch.pending_base_url, &orch.pending_path, pending_id);
    Ok(PersonTokenFlowOutcome::deferred(DeferCreated {
        location,
        requirement,
    }))
}

async fn create_deferred_person_response<P, S, M>(
    service: &PolicyPersonTokenService<P, S, M>,
    ctx: &PersonTokenContext,
    requirement: DeferRequirement,
    agent_jwt: &str,
) -> Result<PersonTokenFlowOutcome, PersonTokenServiceError>
where
    P: PersonTokenPolicy,
    S: PendingStore<PersonPendingRecord>,
    M: AuthJwtMinter + Clone,
{
    let orch = service.orch();
    let id = generate_pending_id();
    let location = pending_location(&orch.pending_base_url, &orch.pending_path, &id);
    let record = PersonPendingRecord::new(
        id,
        PersonPendingContext {
            person_server_url: ctx.person_server_url.clone(),
            resource_url: ctx.resource_url.clone(),
            agent_claims: ctx.agent_claims.clone(),
            resource_claims: ctx.resource_claims.clone(),
            exchange_request: ctx.exchange_request.clone(),
            agent_token: agent_jwt.to_string(),
            federation: None,
        },
        PendingSnapshot::waiting(requirement.clone()),
        orch.pending_ttl_secs,
    );

    service
        .pending
        .create(record)
        .await
        .map_err(|e| PersonTokenServiceError::PendingStore(e.to_string()))?;

    Ok(PersonTokenFlowOutcome::deferred(DeferCreated {
        location,
        requirement,
    }))
}

async fn create_federated_deferred_response<P, S, M>(
    service: &PolicyPersonTokenService<P, S, M>,
    ctx: &PersonTokenContext,
    pending_id: Option<&str>,
    requirement: DeferRequirement,
    federation: FederationPendingState,
    agent_jwt: &str,
) -> Result<PersonTokenFlowOutcome, PersonTokenServiceError>
where
    P: PersonTokenPolicy,
    S: PendingStore<PersonPendingRecord>,
    M: AuthJwtMinter + Clone,
{
    let orch = service.orch();
    let id = pending_id
        .map(str::to_string)
        .unwrap_or_else(generate_pending_id);
    let location = pending_location(&orch.pending_base_url, &orch.pending_path, &id);

    let person_ctx = PersonPendingContext {
        person_server_url: ctx.person_server_url.clone(),
        resource_url: ctx.resource_url.clone(),
        agent_claims: ctx.agent_claims.clone(),
        resource_claims: ctx.resource_claims.clone(),
        exchange_request: ctx.exchange_request.clone(),
        agent_token: agent_jwt.to_string(),
        federation: Some(federation),
    };

    if pending_id.is_some() {
        let Some(mut record) = service
            .pending
            .load(&id)
            .await
            .map_err(|e| PersonTokenServiceError::PendingStore(e.to_string()))?
        else {
            return Ok(PersonTokenFlowOutcome::Gone);
        };
        record.context = person_ctx;
        record.snapshot = PendingSnapshot::waiting(requirement.clone());
        service
            .pending
            .save(&id, record)
            .await
            .map_err(|e| PersonTokenServiceError::PendingStore(e.to_string()))?;
    } else {
        let record = PersonPendingRecord::new(
            id.clone(),
            person_ctx,
            PendingSnapshot::waiting(requirement.clone()),
            orch.pending_ttl_secs,
        );
        service
            .pending
            .create(record)
            .await
            .map_err(|e| PersonTokenServiceError::PendingStore(e.to_string()))?;
    }

    Ok(PersonTokenFlowOutcome::deferred(DeferCreated {
        location,
        requirement,
    }))
}

async fn handle_federated_pending_post<P, S, M>(
    service: &PolicyPersonTokenService<P, S, M>,
    pending_id: &str,
    federation: &FederationPendingState,
    agent_token: &str,
    resource_url: &str,
    input: PendingInput,
) -> Result<PersonTokenFlowOutcome, PersonTokenServiceError>
where
    P: PersonTokenPolicy,
    S: PendingStore<PersonPendingRecord>,
    M: AuthJwtMinter + Clone,
{
    let orch = service.orch();

    if matches!(input, PendingInput::Cancelled) {
        let err =
            AAuthProtocolError::with_description(AAuthErrorCode::AccessDenied, "Request cancelled");
        service
            .pending
            .complete(pending_id, PendingOutcome::Error(err.clone()))
            .await
            .map_err(|e| PersonTokenServiceError::PendingStore(e.to_string()))?;
        return Ok(PersonTokenFlowOutcome::denied(err));
    }

    let signer = crate::person_server::PersonServerOutboundSigner {
        person_server_url: orch.person_server_url.clone(),
        signing_jwk: orch.person_server_signing_jwk.clone(),
        keys: orch.keys.clone(),
    };
    let post_outcome = match post_pending_input(
        &orch.http_client,
        &federation.as_pending_url,
        &input,
        Some(&signer),
    )
    .await
    {
        Ok(outcome) => outcome,
        Err(_) => return Ok(PersonTokenFlowOutcome::BadGateway),
    };

    let poll_outcome = if let Some(body) = post_outcome {
        ServerPollOutcome::AuthToken(body)
    } else {
        match poll_pending_http(
            &orch.http_client,
            ServerPollOptions {
                location_url: federation.as_pending_url.clone(),
                max_poll_duration_secs: orch.federation_poll_max_secs,
                prefer_wait: None,
            },
            &federation.access_server_url,
        )
        .await
        {
            Ok(outcome) => outcome,
            Err(_) => return Ok(PersonTokenFlowOutcome::BadGateway),
        }
    };

    match poll_outcome {
        ServerPollOutcome::AuthToken(body) => {
            if verify_federated_auth_token(
                &body.auth_token,
                &federation.access_server_url,
                resource_url,
                agent_token,
                Arc::clone(&orch.fetcher),
            )
            .await
            .is_err()
            {
                return Ok(PersonTokenFlowOutcome::Unauthorized);
            }
            service
                .pending
                .complete(pending_id, PendingOutcome::AuthToken(body.clone()))
                .await
                .map_err(|e| PersonTokenServiceError::PendingStore(e.to_string()))?;
            Ok(PersonTokenFlowOutcome::granted(body))
        }
        ServerPollOutcome::Deferred {
            requirement,
            location_url,
        } => {
            let Some(mut record) = service
                .pending
                .load(pending_id)
                .await
                .map_err(|e| PersonTokenServiceError::PendingStore(e.to_string()))?
            else {
                return Ok(PersonTokenFlowOutcome::Gone);
            };
            record.snapshot = PendingSnapshot::waiting(requirement.clone());
            record.context.federation = Some(FederationPendingState {
                access_server_url: federation.access_server_url.clone(),
                as_pending_url: location_url,
            });
            service
                .pending
                .save(pending_id, record)
                .await
                .map_err(|e| PersonTokenServiceError::PendingStore(e.to_string()))?;
            let location = pending_location(&orch.pending_base_url, &orch.pending_path, pending_id);
            Ok(PersonTokenFlowOutcome::deferred(DeferCreated {
                location,
                requirement,
            }))
        }
        ServerPollOutcome::Error(err) => {
            service
                .pending
                .complete(pending_id, PendingOutcome::Error(err.clone()))
                .await
                .map_err(|e| PersonTokenServiceError::PendingStore(e.to_string()))?;
            Ok(PersonTokenFlowOutcome::denied(err))
        }
        ServerPollOutcome::Gone => {
            let _ = service.pending.remove(pending_id).await;
            Ok(PersonTokenFlowOutcome::Gone)
        }
    }
}
