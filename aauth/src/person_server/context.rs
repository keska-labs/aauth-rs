use crate::error::{Result, VerifyError, VerifyReason};
use crate::jwt::{AgentClaims, ParsedToken};
use crate::metadata::MetadataFetcher;
use crate::person_server::keys::PersonAuthJwtMinter;
use crate::person_server::service::{PersonServerConfig, PersonTokenContext};
use crate::protocol::{JwtTyp, TokenExchangeRequest, TokenResponseBody};
use crate::resource_verify::{VerifyResourceTokenOptions, verify_resource_token};

impl<F: MetadataFetcher> PersonServerConfig<F> {
    pub async fn verify_token_request(
        &self,
        agent_jwt: &str,
        agent_jkt: &str,
        resource_token: &str,
        exchange_request: TokenExchangeRequest,
    ) -> Result<PersonTokenContext> {
        let agent = match ParsedToken::parse(agent_jwt)? {
            ParsedToken::Agent(c) => c,
            ParsedToken::Auth(_) | ParsedToken::Resource(_) => {
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
            fetcher: &self.fetcher,
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
        agent: &AgentClaims,
    ) -> Result<TokenResponseBody> {
        let auth_jwt = minter.mint_person_auth_jwt(
            &self.person_server_url,
            &self.resource_url,
            agent.identifier(),
            &agent.cnf.jwk,
            Some(sub),
            scope,
        )?;
        Ok(TokenResponseBody {
            auth_token: auth_jwt,
            expires_in: 3600,
        })
    }
}
