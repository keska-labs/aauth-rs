use std::sync::Arc;

use crate::error::{Result, VerifyError, VerifyReason};
use crate::jwt::VerifiedToken;
use crate::person_server::config::PersonServerConfig;
use crate::person_server::keys::PersonAuthJwtMinter;
use crate::person_server::token_context::PersonTokenContext;
use crate::protocol::{JwtTyp, TokenExchangeRequest, TokenResponseBody};
use crate::resource_verify::{VerifyResourceTokenOptions, verify_resource_token};

impl PersonServerConfig {
    pub async fn verify_token_request(
        &self,
        agent_jwt: &str,
        agent_jkt: &str,
        resource_token: &str,
        exchange_request: TokenExchangeRequest,
    ) -> Result<PersonTokenContext> {
        let agent = match VerifiedToken::decode_unverified(agent_jwt)? {
            VerifiedToken::Agent(c) => c,
            VerifiedToken::Auth(_) => {
                return Err(VerifyError::Invalid {
                    typ: JwtTyp::Auth,
                    reason: VerifyReason::WrongTyp,
                }
                .into());
            }
        };

        let resource_claims = verify_resource_token(VerifyResourceTokenOptions {
            jwt: resource_token.to_string(),
            expected_agent: Some(agent.identifier().to_string()),
            expected_agent_jkt: Some(agent_jkt.to_string()),
            fetcher: Arc::clone(&self.fetcher),
        })
        .await?;

        Ok(PersonTokenContext {
            person_server_url: self.person_server_url.clone(),
            resource_url: self.resource_url.clone(),
            agent_claims: agent,
            resource_claims,
            exchange_request,
        })
    }

    pub fn mint_person_auth<M: PersonAuthJwtMinter>(
        &self,
        minter: &M,
        sub: &str,
        scope: Option<&str>,
        agent_sub: &str,
    ) -> TokenResponseBody {
        let auth_jwt = minter.mint_person_auth_jwt(
            &self.person_server_url,
            &self.resource_url,
            agent_sub,
            Some(sub),
            scope,
        );
        TokenResponseBody {
            auth_token: auth_jwt,
            expires_in: 3600,
        }
    }
}
