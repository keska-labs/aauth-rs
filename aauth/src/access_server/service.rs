use crate::access_server::config::AccessServerConfig;
use crate::access_server::token_context::AccessTokenContext;
use crate::deferred::{AuthTokenFlowOutcome, AuthTokenPollOutcome, PendingInput};
use crate::error::{AAuthError, VerifyError, VerifyReason};
use crate::jwt::{VerifiedToken, decode_resource_token_unverified};
use crate::protocol::JwtTyp;

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

impl AccessTokenContext {
    pub fn from_exchange(
        config: &AccessServerConfig,
        request: &crate::protocol::AccessTokenExchangeRequest,
    ) -> Result<Self, AAuthError> {
        let agent = match VerifiedToken::decode_unverified(&request.agent_token)? {
            VerifiedToken::Agent(c) => c,
            VerifiedToken::Auth(_) => {
                return Err(VerifyError::Invalid {
                    typ: JwtTyp::Auth,
                    reason: VerifyReason::WrongTyp,
                }
                .into());
            }
        };
        let resource_claims = decode_resource_token_unverified(&request.resource_token)?;

        Ok(Self {
            access_server_url: config.access_server_url.clone(),
            resource_url: config.resource_url.clone(),
            person_server_url: config.person_server_url.clone(),
            agent_claims: agent,
            resource_claims,
            resource_token: request.resource_token.clone(),
            agent_token: request.agent_token.clone(),
        })
    }
}
