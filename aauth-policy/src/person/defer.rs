use aauth::DeferCreated;
use aauth::DeferRequirement;
use aauth::PendingOutcome;
use aauth::PendingSnapshot;
use aauth::PersonTokenContext;
use aauth::generate_pending_id;
use aauth::interaction_code::{canonicalize_code, generate_code};
use aauth::pending_location;
use aauth::person_server::federation::FederationOutcome;
use aauth::person_server::keys::PersonAuthJwtMinter;
use aauth::person_server::outcome::PersonTokenFlowOutcome;

use crate::PersonOrchestrationError;
use crate::PersonTokenDecision;
use crate::PersonTokenPolicy;
use crate::store::{
    FederationPendingState, PendingStore, PersonPendingContext, PersonPendingRecord,
};

use super::PersonTokenServiceError;
use super::PolicyPersonTokenService;

impl<P, S, M> PolicyPersonTokenService<P, S, M> {
    pub(super) async fn apply_person_decision(
        &self,
        ctx: &PersonTokenContext,
        decision: PersonTokenDecision,
        agent_jwt: &str,
    ) -> Result<PersonTokenFlowOutcome, PersonTokenServiceError<S::Error>>
    where
        P: PersonTokenPolicy,
        S: PendingStore<PersonPendingRecord>,
        M: PersonAuthJwtMinter + Clone,
    {
        match decision {
            PersonTokenDecision::Grant(grant) => {
                let body = self.config.mint_person_auth(
                    &self.minter,
                    &grant.sub,
                    grant.scope.as_deref(),
                    ctx.agent_claims.identifier(),
                );
                Ok(PersonTokenFlowOutcome::granted(body))
            }
            PersonTokenDecision::Federate => match self
                .config
                .federate_to_access_server(&ctx.exchange_request.resource_token, agent_jwt)
                .await
            {
                Ok(FederationOutcome::Complete(body)) => Ok(PersonTokenFlowOutcome::granted(body)),
                Ok(FederationOutcome::Deferred {
                    requirement,
                    as_pending_url,
                    access_server_url,
                }) => {
                    self.create_federated_deferred_response(
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
                self.create_deferred_person_response(ctx, requirement, agent_jwt)
                    .await
            }
        }
    }

    pub(super) async fn apply_person_pending_decision(
        &self,
        ctx: &PersonTokenContext,
        pending_id: &str,
        decision: PersonTokenDecision,
        agent_jwt: &str,
    ) -> Result<PersonTokenFlowOutcome, PersonTokenServiceError<S::Error>>
    where
        P: PersonTokenPolicy,
        S: PendingStore<PersonPendingRecord>,
        M: PersonAuthJwtMinter + Clone,
    {
        match decision {
            PersonTokenDecision::Grant(grant) => {
                let body = self.config.mint_person_auth(
                    &self.minter,
                    &grant.sub,
                    grant.scope.as_deref(),
                    ctx.agent_claims.identifier(),
                );
                self.pending
                    .complete(pending_id, PendingOutcome::AuthToken(body.clone()))
                    .await
                    .map_err(PersonTokenServiceError::PendingStore)?;
                Ok(PersonTokenFlowOutcome::granted(body))
            }
            PersonTokenDecision::Federate => match self
                .config
                .federate_to_access_server(&ctx.exchange_request.resource_token, agent_jwt)
                .await
            {
                Ok(FederationOutcome::Complete(body)) => {
                    self.pending
                        .complete(pending_id, PendingOutcome::AuthToken(body.clone()))
                        .await
                        .map_err(PersonTokenServiceError::PendingStore)?;
                    Ok(PersonTokenFlowOutcome::granted(body))
                }
                Ok(FederationOutcome::Deferred {
                    requirement,
                    as_pending_url,
                    access_server_url,
                }) => {
                    self.create_federated_deferred_response(
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
                self.pending
                    .complete(pending_id, PendingOutcome::Error(err.clone()))
                    .await
                    .map_err(PersonTokenServiceError::PendingStore)?;
                Ok(PersonTokenFlowOutcome::denied(err))
            }
            PersonTokenDecision::Defer(requirement) => {
                self.update_person_pending_defer(pending_id, requirement)
                    .await
            }
        }
    }

    pub(super) async fn update_person_pending_defer(
        &self,
        pending_id: &str,
        requirement: DeferRequirement,
    ) -> Result<PersonTokenFlowOutcome, PersonTokenServiceError<S::Error>>
    where
        S: PendingStore<PersonPendingRecord>,
    {
        let Some(mut record) = self
            .pending
            .load(pending_id)
            .await
            .map_err(PersonTokenServiceError::PendingStore)?
        else {
            return Ok(PersonTokenFlowOutcome::Gone);
        };
        record.snapshot = PendingSnapshot::waiting(requirement.clone());
        self.pending
            .save(pending_id, record)
            .await
            .map_err(PersonTokenServiceError::PendingStore)?;

        let location = pending_location(
            &self.config.pending_base_url,
            &self.config.pending_path,
            pending_id,
        );
        Ok(PersonTokenFlowOutcome::deferred(DeferCreated {
            location,
            requirement,
        }))
    }

    pub(super) async fn create_deferred_person_response(
        &self,
        ctx: &PersonTokenContext,
        requirement: DeferRequirement,
        agent_jwt: &str,
    ) -> Result<PersonTokenFlowOutcome, PersonTokenServiceError<S::Error>>
    where
        S: PendingStore<PersonPendingRecord>,
    {
        let id = generate_pending_id();
        let location = pending_location(
            &self.config.pending_base_url,
            &self.config.pending_path,
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
            self.config.pending_ttl_secs,
        );

        self.pending
            .create(record)
            .await
            .map_err(PersonTokenServiceError::PendingStore)?;

        Ok(PersonTokenFlowOutcome::deferred(DeferCreated {
            location,
            requirement,
        }))
    }

    pub(super) async fn create_resource_initiated_deferred_response(
        &self,
        ctx: &PersonTokenContext,
        agent_jwt: &str,
    ) -> Result<PersonTokenFlowOutcome, PersonTokenServiceError<S::Error>>
    where
        S: PendingStore<PersonPendingRecord>,
    {
        let resource_ix = ctx
            .resource_claims
            .interaction
            .clone()
            .ok_or(PersonOrchestrationError::MissingResourceInteraction)?;

        let ps_code = generate_code();
        let requirement = DeferRequirement::Interaction {
            url: self.config.interaction_url.clone(),
            code: ps_code.clone(),
        };

        let id = generate_pending_id();
        let location = pending_location(
            &self.config.pending_base_url,
            &self.config.pending_path,
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
            self.config.pending_ttl_secs,
        );

        self.pending
            .create(record)
            .await
            .map_err(PersonTokenServiceError::PendingStore)?;

        Ok(PersonTokenFlowOutcome::deferred(DeferCreated {
            location,
            requirement,
        }))
    }
}
