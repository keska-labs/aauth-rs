use std::sync::Arc;

use crate::deferred::AuthTokenPollOutcome;
use crate::deferred::DeferCreated;
use crate::jwt::AgentClaims;
use crate::protocol::AAuthProtocolError;
use crate::protocol::ResourceInteractionClaim;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ResourceAccessContext {
    pub resource_url: String,
    pub agent_claims: AgentClaims,
    pub scope: Option<String>,
}

/// Resource-managed consent evaluation result.
///
/// Spec: `draft-hardt-oauth-aauth-protocol.md#resource-managed-auth`
#[derive(Debug, Clone, PartialEq)]
pub enum ResourceConsentFlowOutcome {
    GrantOpaque(String),
    Deferred(DeferCreated),
    Denied(AAuthProtocolError),
}

/// Resource pending poll result (same wire shape as auth token poll).
pub type ResourcePollOutcome = AuthTokenPollOutcome;

#[derive(Clone)]
pub struct ResourceAccessConfig {
    pub interaction_url: String,
    pub pending_base_url: String,
    pub pending_path: String,
    pub pending_ttl_secs: u64,
}

#[trait_variant::make(ResourceAccessService: Send)]
#[dynosaur::dynosaur(pub DynResourceAccessService = dyn(box) ResourceAccessService, bridge(dyn))]
pub trait LocalResourceAccessService: Sync {
    type Error: std::error::Error + Send + Sync + 'static;

    async fn consent_for_agent(
        &self,
        ctx: ResourceAccessContext,
    ) -> Result<ResourceConsentFlowOutcome, Self::Error>;

    async fn poll_pending(&self, pending_id: &str) -> Result<ResourcePollOutcome, Self::Error>;

    /// Validate an opaque token from `Authorization: AAuth …` / `AAuth-Access`.
    ///
    /// Spec: `draft-hardt-oauth-aauth-protocol.md#aauth-access`
    fn validate_opaque(&self, token: &str, agent_id: &str) -> bool;
}

/// Marker service for [`ResourceAccessMode`] variants that do not use a
/// consent service (`IdentityBased`, `PsAsserted`).
#[derive(Clone, Copy, Debug, Default)]
pub struct NoResourceAccessService;

impl ResourceAccessService for NoResourceAccessService {
    type Error = std::convert::Infallible;

    async fn consent_for_agent(
        &self,
        _ctx: ResourceAccessContext,
    ) -> Result<ResourceConsentFlowOutcome, Self::Error> {
        unreachable!("NoResourceAccessService is only for IdentityBased/PsAsserted modes")
    }

    async fn poll_pending(&self, _pending_id: &str) -> Result<ResourcePollOutcome, Self::Error> {
        unreachable!("NoResourceAccessService is only for IdentityBased/PsAsserted modes")
    }

    fn validate_opaque(&self, _token: &str, _agent_id: &str) -> bool {
        false
    }
}

/// How a resource server evaluates access for incoming agent requests.
///
/// Spec: `draft-hardt-oauth-aauth-protocol.md` resource access modes
/// (`#overview-identity-access`, `#overview-resource-managed`, PS-asserted / federated).
#[derive(Clone)]
pub enum ResourceAccessMode<S = NoResourceAccessService>
where
    S: ResourceAccessService,
{
    /// Grant based on a verified agent token identity alone.
    ///
    /// Accepts only `typ: aa-agent+jwt`. Missing agent credential →
    /// `401` + `AAuth-Requirement: requirement=agent-token`.
    ///
    /// Spec: `draft-hardt-oauth-aauth-protocol.md#overview-identity-access`,
    /// `#requirement-agent-token`
    IdentityBased,
    /// Delegate authorization to the agent's Person Server (or Access Server when federated).
    ///
    /// With `access_server_url: None`, three-party PS-asserted access
    /// (`#fig-ps-asserted`). With `Some(as_url)`, four-party federated access
    /// (`#fig-federated`); resource token `aud` is the AS.
    PsAsserted {
        require_auth_token: bool,
        access_server_url: Option<String>,
        person_server_fallback: Option<String>,
    },
    /// Resource manages authorization via interaction and opaque access tokens.
    ///
    /// Spec: `draft-hardt-oauth-aauth-protocol.md#overview-resource-managed`
    ResourceManaged { service: S },
}

/// Context passed to [`ResourceInteractionProvider::interaction_for`].
#[derive(Debug, Clone)]
pub struct ResourceInteractionContext {
    pub resource_url: String,
    pub agent: AgentClaims,
    pub agent_jkt: String,
}

/// Optional hook for PS-asserted resources to embed a resource-initiated interaction claim.
///
/// Spec: `draft-hardt-oauth-aauth-protocol.md#resource-initiated-interaction`
pub trait ResourceInteractionProvider: Send + Sync {
    fn interaction_for(&self, ctx: &ResourceInteractionContext)
    -> Option<ResourceInteractionClaim>;
}

impl<T: ResourceInteractionProvider + ?Sized> ResourceInteractionProvider for Arc<T> {
    fn interaction_for(
        &self,
        ctx: &ResourceInteractionContext,
    ) -> Option<ResourceInteractionClaim> {
        (**self).interaction_for(ctx)
    }
}

/// Marker provider when no resource-initiated interaction claim is needed.
#[derive(Clone, Copy, Debug, Default)]
pub struct NoResourceInteraction;

impl ResourceInteractionProvider for NoResourceInteraction {
    fn interaction_for(
        &self,
        _ctx: &ResourceInteractionContext,
    ) -> Option<ResourceInteractionClaim> {
        None
    }
}
