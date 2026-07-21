use std::sync::Arc;

use aauth::DeferCreated;
use aauth::DeferRequirement;
use aauth::PendingInput;
use aauth::PendingOutcome;
use aauth::PendingSnapshot;
use aauth::PersonTokenContext;
use aauth::ServerPollOptions;
use aauth::ServerPollOutcome;
use aauth::generate_pending_id;
use aauth::pending_location;
use aauth::person_server::federation::verify_federated_auth_token;
use aauth::person_server::keys::PersonAuthJwtMinter;
use aauth::person_server::outcome::PersonTokenFlowOutcome;
use aauth::poll_pending_http;
use aauth::post_pending_input;
use aauth::protocol::{AAuthErrorCode, AAuthProtocolError};

use crate::PersonTokenPolicy;
use crate::store::{
    FederationPendingState, PendingStore, PersonPendingContext, PersonPendingRecord,
};

use super::PersonTokenServiceError;
use super::PolicyPersonTokenService;

pub(super) async fn create_federated_deferred_response<P, S, M>(
    service: &PolicyPersonTokenService<P, S, M>,
    ctx: &PersonTokenContext,
    pending_id: Option<&str>,
    requirement: DeferRequirement,
    federation: FederationPendingState,
    agent_jwt: &str,
) -> Result<PersonTokenFlowOutcome, PersonTokenServiceError<S::Error>>
where
    P: PersonTokenPolicy,
    S: PendingStore<PersonPendingRecord>,
    M: PersonAuthJwtMinter + Clone,
{
    let id = pending_id
        .map(str::to_string)
        .unwrap_or_else(generate_pending_id);
    let location = pending_location(
        &service.config.pending_base_url,
        &service.config.pending_path,
        &id,
    );

    let person_ctx = PersonPendingContext {
        person_server_url: ctx.person_server_url.clone(),
        resource_url: ctx.resource_url.clone(),
        agent_claims: ctx.agent_claims.clone(),
        resource_claims: ctx.resource_claims.clone(),
        exchange_request: ctx.exchange_request.clone(),
        agent_token: agent_jwt.to_string(),
        federation: Some(federation),
        resource_interaction: None,
        ps_interaction_code: None,
        interaction_code_consumed: false,
    };

    if pending_id.is_some() {
        let Some(mut record) = service.pending.load(&id).await.map_err(PersonTokenServiceError::PendingStore)? else {
            return Ok(PersonTokenFlowOutcome::Gone);
        };
        record.context = person_ctx;
        record.snapshot = PendingSnapshot::waiting(requirement.clone());
        service.pending.save(&id, record).await.map_err(PersonTokenServiceError::PendingStore)?;
    } else {
        let record = PersonPendingRecord::new(
            id.clone(),
            person_ctx,
            PendingSnapshot::waiting(requirement.clone()),
            service.config.pending_ttl_secs,
        );
        service.pending.create(record).await.map_err(PersonTokenServiceError::PendingStore)?;
    }

    Ok(PersonTokenFlowOutcome::deferred(DeferCreated {
        location,
        requirement,
    }))
}

pub(super) async fn handle_federated_pending_post<P, S, M>(
    service: &PolicyPersonTokenService<P, S, M>,
    pending_id: &str,
    federation: &FederationPendingState,
    agent_token: &str,
    resource_url: &str,
    input: PendingInput,
) -> Result<PersonTokenFlowOutcome, PersonTokenServiceError<S::Error>>
where
    P: PersonTokenPolicy,
    S: PendingStore<PersonPendingRecord>,
    M: PersonAuthJwtMinter + Clone,
{
    if matches!(input, PendingInput::Cancelled) {
        let err =
            AAuthProtocolError::with_description(AAuthErrorCode::AccessDenied, "Request cancelled");
        service
            .pending
            .complete(pending_id, PendingOutcome::Error(err.clone()))
            .await
            .map_err(PersonTokenServiceError::PendingStore)?;
        return Ok(PersonTokenFlowOutcome::denied(err));
    }

    let signer = aauth::PersonServerOutboundSigner {
        person_server_url: service.config.person_server_url.clone(),
        signing_jwk: service.config.person_server_signing_jwk(),
        keys: service.config.keys.clone(),
    };
    let post_outcome = match post_pending_input(
        &service.config.http_client,
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
            &service.config.http_client,
            ServerPollOptions {
                location_url: federation.as_pending_url.clone(),
                max_poll_duration_secs: service.config.federation_poll_max_secs,
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
                Arc::clone(&service.config.fetcher),
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
                .map_err(PersonTokenServiceError::PendingStore)?;
            Ok(PersonTokenFlowOutcome::granted(body))
        }
        ServerPollOutcome::Deferred {
            requirement,
            location_url,
        } => {
            let Some(mut record) = service.pending.load(pending_id).await.map_err(PersonTokenServiceError::PendingStore)? else {
                return Ok(PersonTokenFlowOutcome::Gone);
            };
            record.snapshot = PendingSnapshot::waiting(requirement.clone());
            record.context.federation = Some(FederationPendingState {
                access_server_url: federation.access_server_url.clone(),
                as_pending_url: location_url,
            });
            service.pending.save(pending_id, record).await.map_err(PersonTokenServiceError::PendingStore)?;
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
        ServerPollOutcome::Error(err) => {
            service
                .pending
                .complete(pending_id, PendingOutcome::Error(err.clone()))
                .await
                .map_err(PersonTokenServiceError::PendingStore)?;
            Ok(PersonTokenFlowOutcome::denied(err))
        }
        ServerPollOutcome::Gone => {
            let _ = service.pending.remove(pending_id).await;
            Ok(PersonTokenFlowOutcome::Gone)
        }
    }
}
