use std::sync::Arc;

use crate::error::{AAuthError, Result};
use crate::jwt::VerifiedToken;
use crate::metadata::MetadataFetcher;
use crate::server::person::keys::AuthJwtMinter;
use crate::server::policy::{AuthGrant, PersonTokenContext, PersonTokenDecision};
use crate::server::resource::{VerifyResourceTokenOptions, verify_resource_token};
use crate::types::TokenExchangeRequest;

use super::federation::FederationConfig;

#[derive(Clone)]
pub struct PersonOrchestrateConfig {
    pub person_server_url: String,
    pub resource_url: String,
    pub interaction_url: String,
    pub pending_base_url: String,
    pub pending_path: String,
    pub pending_ttl_secs: u64,
    pub fetcher: Arc<dyn MetadataFetcher>,
    pub http_client: reqwest::Client,
    pub federation: FederationConfig,
}

pub async fn verify_person_token_request(
    config: &PersonOrchestrateConfig,
    agent_jwt: &str,
    resource_token: &str,
    exchange_request: TokenExchangeRequest,
) -> Result<PersonTokenContext> {
    let agent = match VerifiedToken::decode_unverified(agent_jwt)? {
        VerifiedToken::Agent(c) => c,
        _ => {
            return Err(AAuthError::Message(
                "token exchange requires agent token in Signature-Key".into(),
            ));
        }
    };

    let resource_claims = verify_resource_token(VerifyResourceTokenOptions {
        jwt: resource_token.to_string(),
        expected_agent: Some(agent.iss.clone()),
        expected_agent_jkt: None,
        fetcher: Arc::clone(&config.fetcher),
    })
    .await?;

    Ok(PersonTokenContext {
        person_server_url: config.person_server_url.clone(),
        resource_url: config.resource_url.clone(),
        agent_claims: agent,
        resource_claims,
        exchange_request,
    })
}

pub fn mint_person_auth<M: AuthJwtMinter>(
    minter: &M,
    config: &PersonOrchestrateConfig,
    grant: &AuthGrant,
    agent_iss: &str,
) -> crate::types::TokenResponseBody {
    let auth_jwt = minter.mint_auth_jwt(
        &config.person_server_url,
        &config.resource_url,
        agent_iss,
        Some(&grant.sub),
        grant.scope.as_deref(),
    );
    crate::types::TokenResponseBody {
        auth_token: auth_jwt,
        expires_in: 3600,
    }
}

pub fn person_decision_aud_is_ps(ctx: &PersonTokenContext) -> bool {
    ctx.audience_is_person_server()
}

pub fn map_person_decision_for_aud(
    ctx: &PersonTokenContext,
    decision: PersonTokenDecision,
) -> PersonTokenDecision {
    match decision {
        PersonTokenDecision::Grant(_grant) if !ctx.audience_is_person_server() => {
            PersonTokenDecision::Federate
        }
        other => other,
    }
}
