use crate::deferred::{AuthTokenFlowOutcome, AuthTokenPollOutcome, PendingInput};
use crate::error::{AAuthError, VerifyError, VerifyReason};
use crate::jwt::{AgentClaims, ParsedToken, ResourceClaims};
use crate::keys::TestKeys;
use crate::metadata::MetadataFetcher;
use crate::protocol::JwtTyp;

#[derive(Clone)]
pub struct AccessServerConfig<F: MetadataFetcher = crate::metadata::StaticMetadataFetcher> {
    pub keys: TestKeys,
    pub access_server_url: String,
    pub resource_url: String,
    pub person_server_url: String,
    pub access_jwks_uri: String,
    pub pending_base_url: String,
    pub pending_path: String,
    pub pending_ttl_secs: u64,
    pub fetcher: F,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AccessTokenContext {
    pub access_server_url: String,
    pub resource_url: String,
    pub person_server_url: String,
    pub agent_claims: AgentClaims,
    pub resource_claims: ResourceClaims,
    pub resource_token: String,
    pub agent_token: String,
}

#[trait_variant::make(AccessTokenService: Send)]
#[dynosaur::dynosaur(pub DynAccessTokenService = dyn(box) AccessTokenService, bridge(dyn))]
pub trait LocalAccessTokenService: Sync {
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
    pub fn from_exchange<F: crate::metadata::MetadataFetcher>(
        config: &AccessServerConfig<F>,
        request: &crate::protocol::AccessTokenExchangeRequest,
    ) -> Result<Self, AAuthError> {
        let agent = match ParsedToken::parse(&request.agent_token)? {
            ParsedToken::Agent(c) => c,
            ParsedToken::Auth(_) | ParsedToken::Resource(_) => {
                return Err(VerifyError::Invalid {
                    typ: JwtTyp::Auth,
                    reason: VerifyReason::WrongTyp,
                }
                .into());
            }
        };
        let resource_claims = match ParsedToken::parse(&request.resource_token)? {
            ParsedToken::Resource(c) => c,
            _ => {
                return Err(VerifyError::Invalid {
                    typ: JwtTyp::Resource,
                    reason: VerifyReason::WrongTyp,
                }
                .into());
            }
        };

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
