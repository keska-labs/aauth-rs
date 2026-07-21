use crate::deferred::{DeferRequirement};
use crate::error::{Result, VerifyError, VerifyReason};
use crate::jwt::ParsedToken;
use crate::metadata::MetadataFetcher;
use crate::person_server::access_client::{AccessServerClient, AccessServerExchangeOutcome};
use crate::person_server::service::PersonServerConfig;
use crate::protocol::{AccessTokenExchangeRequest, JwtTyp, TokenResponseBody};
use crate::resource_verify::{VerifyTokenOptions, verify_token};

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum FederationOutcome {
    Complete(TokenResponseBody),
    Deferred {
        requirement: DeferRequirement,
        as_pending_url: String,
        access_server_url: String,
    },
}

impl<F: MetadataFetcher, C: AccessServerClient> PersonServerConfig<F, C> {
    /// Federate a resource-token exchange to the Access Server named in `aud`.
    ///
    /// Spec: `draft-hardt-oauth-aauth-protocol.md#access-server-federation`,
    /// `#as-token-endpoint`, `#ps-as-federation`, `#access-server-metadata`
    pub async fn federate_to_access_server(
        &self,
        resource_token: &str,
        agent_token: &str,
    ) -> Result<FederationOutcome> {
        let claims = match ParsedToken::parse(resource_token)? {
            ParsedToken::Resource(c) => c,
            _ => {
                return Err(VerifyError::Invalid {
                    typ: JwtTyp::Resource,
                    reason: VerifyReason::WrongTyp,
                }
                .into());
            }
        };
        let access_server_url = claims.aud.trim_end_matches('/').to_string();

        let metadata = self.access_server.fetch_metadata(&access_server_url).await?;
        metadata.validate()?;

        let request = AccessTokenExchangeRequest {
            resource_token: resource_token.to_string(),
            agent_token: agent_token.to_string(),
            upstream_token: None,
            subagent_token: None,
        };

        match self
            .access_server
            .exchange_token(&metadata.token_endpoint, &request)
            .await?
        {
            AccessServerExchangeOutcome::Complete(token_body) => {
                verify_federated_auth_token(
                    &token_body.auth_token,
                    &access_server_url,
                    &self.resource_url,
                    agent_token,
                    &self.fetcher,
                )
                .await?;
                Ok(FederationOutcome::Complete(token_body))
            }
            AccessServerExchangeOutcome::Deferred {
                requirement,
                as_pending_url,
            } => Ok(FederationOutcome::Deferred {
                requirement,
                as_pending_url,
                access_server_url,
            }),
        }
    }
}

/// Verify an auth token minted by an AS before returning it to the agent.
///
/// Spec: Auth Token Delivery under `draft-hardt-oauth-aauth-protocol.md#as-token-endpoint`,
/// `#auth-token-verification`
pub async fn verify_federated_auth_token<F: MetadataFetcher>(
    auth_token: &str,
    expected_iss: &str,
    expected_aud: &str,
    agent_token: &str,
    fetcher: &F,
) -> Result<()> {
    let agent = match ParsedToken::parse(agent_token)? {
        ParsedToken::Agent(c) => c,
        _ => {
            return Err(VerifyError::Invalid {
                typ: JwtTyp::Agent,
                reason: VerifyReason::WrongTyp,
            }
            .into());
        }
    };

    let agent_jkt = crate::jwt::jwk_thumbprint(&agent.cnf.jwk)?;

    let verified = verify_token(VerifyTokenOptions {
        jwt: auth_token.to_string(),
        http_signature_thumbprint: agent_jkt,
        fetcher,
    })
    .await?;

    let auth = match verified {
        ParsedToken::Auth(c) => c,
        _ => {
            return Err(VerifyError::Invalid {
                typ: JwtTyp::Auth,
                reason: VerifyReason::ExpectedAuth,
            }
            .into());
        }
    };

    if auth.iss.trim_end_matches('/') != expected_iss.trim_end_matches('/') {
        return Err(VerifyError::IssMismatch.into());
    }
    if auth.aud.trim_end_matches('/') != expected_aud.trim_end_matches('/') {
        return Err(VerifyError::AudMismatch.into());
    }
    if auth.agent != agent.identifier() {
        return Err(VerifyError::AgentMismatch.into());
    }

    Ok(())
}
