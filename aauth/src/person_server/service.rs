use crate::deferred::{AuthTokenFlowOutcome, AuthTokenPollOutcome, DeferCreated, PendingInput};
use crate::jwt::{AgentClaims, ResourceClaims};
use crate::keys::TestKeys;
use crate::metadata::MetadataFetcher;
use crate::protocol::{AAuthProtocolError, PendingBody, TokenExchangeRequest, TokenResponseBody};

use crate::http_util::normalize_server_url;

#[derive(Clone)]
pub struct PersonServerConfig<F: MetadataFetcher = crate::metadata::StaticMetadataFetcher> {
    pub keys: TestKeys,
    pub person_server_url: String,
    pub resource_url: String,
    pub person_jwks_uri: String,
    pub interaction_url: String,
    pub pending_base_url: String,
    pub pending_path: String,
    pub pending_ttl_secs: u64,
    pub fetcher: F,
    pub http_client: reqwest::Client,
    /// Max seconds for federation pending polls (default 300).
    pub federation_poll_max_secs: Option<u64>,
}

impl<F: MetadataFetcher> PersonServerConfig<F> {
    pub fn person_server_signing_jwk(&self) -> crate::jwt::SigningJwk {
        self.keys.person_server.signing_jwk()
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PersonTokenContext {
    pub person_server_url: String,
    pub resource_url: String,
    pub agent_claims: AgentClaims,
    pub resource_claims: ResourceClaims,
    pub exchange_request: TokenExchangeRequest,
}

impl PersonTokenContext {
    pub fn audience_is_person_server(&self) -> bool {
        normalize_server_url(&self.resource_claims.aud)
            == normalize_server_url(&self.person_server_url)
    }
}

/// Person Server token exchange / resume result (includes federation-specific outcomes).
#[derive(Debug, Clone, PartialEq)]
pub enum PersonTokenFlowOutcome {
    Granted(TokenResponseBody),
    Deferred(DeferCreated),
    Denied(AAuthProtocolError),
    Gone,
    Unauthorized,
    BadGateway,
}

impl PersonTokenFlowOutcome {
    pub fn granted(body: TokenResponseBody) -> Self {
        Self::Granted(body)
    }

    pub fn deferred(defer: DeferCreated) -> Self {
        Self::Deferred(defer)
    }

    pub fn denied(err: AAuthProtocolError) -> Self {
        Self::Denied(err)
    }

    pub fn into_auth_flow(self) -> Option<AuthTokenFlowOutcome> {
        match self {
            Self::Granted(body) => Some(AuthTokenFlowOutcome::Granted(body)),
            Self::Deferred(defer) => Some(AuthTokenFlowOutcome::Deferred(defer)),
            Self::Denied(err) => Some(AuthTokenFlowOutcome::Denied(err)),
            Self::Gone => Some(AuthTokenFlowOutcome::Gone),
            Self::Unauthorized | Self::BadGateway => None,
        }
    }
}

/// Outcome of starting a PS interaction page visit (`GET ?code=`).
#[derive(Debug, Clone)]
pub enum PersonInteractionOutcome {
    /// Redirect the user to the resource interaction URL (resource-initiated chain).
    Redirect(String),
    /// Interaction code unknown or already consumed.
    InvalidCode,
    /// Pending request TTL expired.
    Expired,
    /// No resource chain — return pending snapshot for integrator consent UI.
    Pending(PendingBody),
}

#[trait_variant::make(PersonTokenService: Send)]
#[dynosaur::dynosaur(pub DynPersonTokenService = dyn(box) PersonTokenService, bridge(dyn))]
pub trait LocalPersonTokenService: Sync {
    type Error: std::error::Error + Send + Sync + 'static;

    async fn exchange_token(
        &self,
        ctx: PersonTokenContext,
        agent_jwt: &str,
    ) -> Result<PersonTokenFlowOutcome, Self::Error>;

    async fn poll_pending(&self, pending_id: &str) -> Result<AuthTokenPollOutcome, Self::Error>;

    async fn resume_pending(
        &self,
        pending_id: &str,
        input: PendingInput,
    ) -> Result<PersonTokenFlowOutcome, Self::Error>;

    async fn begin_interaction(&self, code: &str) -> Result<PersonInteractionOutcome, Self::Error>;

    async fn resolve_interaction_callback(
        &self,
        pending_id: &str,
        callback_error: Option<&str>,
    ) -> Result<PersonTokenFlowOutcome, Self::Error>;
}
