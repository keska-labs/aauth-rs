use crate::deferred::{
    DeferCreated, DeferRequirement, FederationPendingState, PendingOutcome, PendingSnapshot,
    PendingStore, PersonPendingContext, PersonPendingRecord, generate_pending_id, pending_location,
};
use crate::error::AAuthError;
use crate::interaction_code::{canonicalize_code, generate_code};
use crate::person_server::context::mint_person_auth;
use crate::person_server::federation::{FederationOutcome, federate_to_access_server};
use crate::person_server::keys::PersonAuthJwtMinter;
use crate::person_server::outcome::PersonTokenFlowOutcome;
use crate::person_server::service::{PersonTokenServiceError, PolicyPersonTokenService};
use crate::policy::{PersonTokenContext, PersonTokenDecision, PersonTokenPolicy};

use super::federation_pending::create_federated_deferred_response;

pub(super) async fn apply_person_decision<P, S, M>(
    service: &PolicyPersonTokenService<P, S, M>,
    ctx: &PersonTokenContext,
    decision: PersonTokenDecision,
    agent_jwt: &str,
) -> Result<PersonTokenFlowOutcome, PersonTokenServiceError>
where
    P: PersonTokenPolicy,
    S: PendingStore<PersonPendingRecord>,
    M: PersonAuthJwtMinter + Clone,
{
    match decision {
        PersonTokenDecision::Grant(grant) => {
            let body = mint_person_auth(
                &service.minter,
                &service.config,
                &grant,
                ctx.agent_claims.identifier(),
            );
            Ok(PersonTokenFlowOutcome::granted(body))
        }
        PersonTokenDecision::Federate => match federate_to_access_server(
            &service.config.http_client,
            &service.config,
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

pub(super) async fn apply_person_pending_decision<P, S, M>(
    service: &PolicyPersonTokenService<P, S, M>,
    ctx: &PersonTokenContext,
    pending_id: &str,
    decision: PersonTokenDecision,
    agent_jwt: &str,
) -> Result<PersonTokenFlowOutcome, PersonTokenServiceError>
where
    P: PersonTokenPolicy,
    S: PendingStore<PersonPendingRecord>,
    M: PersonAuthJwtMinter + Clone,
{
    match decision {
        PersonTokenDecision::Grant(grant) => {
            let body = mint_person_auth(
                &service.minter,
                &service.config,
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
            &service.config.http_client,
            &service.config,
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

pub(super) async fn update_person_pending_defer<P, S, M>(
    service: &PolicyPersonTokenService<P, S, M>,
    pending_id: &str,
    requirement: DeferRequirement,
) -> Result<PersonTokenFlowOutcome, PersonTokenServiceError>
where
    P: PersonTokenPolicy,
    S: PendingStore<PersonPendingRecord>,
    M: PersonAuthJwtMinter + Clone,
{
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

    let location = pending_location(
        &service.config.pending_base_url,
        &service.config.pending_path,
        pending_id,
    );
    Ok(PersonTokenFlowOutcome::deferred(DeferCreated {
        location,
        requirement,
    }))
}

pub(super) async fn create_deferred_person_response<P, S, M>(
    service: &PolicyPersonTokenService<P, S, M>,
    ctx: &PersonTokenContext,
    requirement: DeferRequirement,
    agent_jwt: &str,
) -> Result<PersonTokenFlowOutcome, PersonTokenServiceError>
where
    P: PersonTokenPolicy,
    S: PendingStore<PersonPendingRecord>,
    M: PersonAuthJwtMinter + Clone,
{
    let id = generate_pending_id();
    let location = pending_location(
        &service.config.pending_base_url,
        &service.config.pending_path,
        &id,
    );
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
            resource_interaction: None,
            ps_interaction_code: None,
            interaction_code_consumed: false,
        },
        PendingSnapshot::waiting(requirement.clone()),
        service.config.pending_ttl_secs,
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

pub(super) async fn create_resource_initiated_deferred_response<P, S, M>(
    service: &PolicyPersonTokenService<P, S, M>,
    ctx: &PersonTokenContext,
    agent_jwt: &str,
) -> Result<PersonTokenFlowOutcome, PersonTokenServiceError>
where
    P: PersonTokenPolicy,
    S: PendingStore<PersonPendingRecord>,
    M: PersonAuthJwtMinter + Clone,
{
    let resource_ix = ctx.resource_claims.interaction.clone().ok_or_else(|| {
        PersonTokenServiceError::Orchestration(AAuthError::Message(
            "resource token missing interaction claim".into(),
        ))
    })?;

    let ps_code = generate_code();
    let requirement = DeferRequirement::Interaction {
        url: service.config.interaction_url.clone(),
        code: ps_code.clone(),
    };

    let id = generate_pending_id();
    let location = pending_location(
        &service.config.pending_base_url,
        &service.config.pending_path,
        &id,
    );
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
            resource_interaction: Some(resource_ix),
            ps_interaction_code: Some(canonicalize_code(&ps_code)),
            interaction_code_consumed: false,
        },
        PendingSnapshot::waiting(requirement.clone()),
        service.config.pending_ttl_secs,
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
