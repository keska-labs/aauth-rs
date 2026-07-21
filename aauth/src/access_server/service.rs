use crate::access_server::config::AccessServerConfig;
use crate::access_server::token_context::AccessTokenContext;
use crate::deferred::{AuthTokenFlowOutcome, AuthTokenPollOutcome, PendingInput};
use crate::error::AAuthError;
use crate::jwt::{VerifiedToken, decode_resource_token_unverified};

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
