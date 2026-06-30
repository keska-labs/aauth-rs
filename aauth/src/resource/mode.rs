use crate::deferred::InMemoryResourcePendingStore;
use crate::resource::service::{PolicyResourceAccessService, ResourceAccessService};

/// How a resource server evaluates access for incoming agent requests.
#[derive(Clone)]
pub enum ResourceAccessMode<S = ResourceAccessPolicyService>
where
    S: ResourceAccessService,
{
    /// Grant based on verified agent or auth token identity alone.
    IdentityBased,
    /// Delegate authorization to the agent's Person Server (or Access Server when federated).
    PsAsserted {
        require_auth_token: bool,
        access_server_url: Option<String>,
        person_server_fallback: Option<String>,
    },
    /// Resource manages authorization via interaction and opaque access tokens.
    ResourceManaged { service: S },
}

/// Default resource-managed mode using in-memory policy, pending store, and opaque tokens.
pub type ResourceAccessPolicyService = PolicyResourceAccessService<
    crate::policy::AlwaysGrantResourcePolicy,
    InMemoryResourcePendingStore,
    crate::resource::InMemoryOpaqueAccessStore,
>;

/// Type-erased mode for callers that do not need resource-managed generics.
pub type ResourceAccessPolicy = ResourceAccessMode<ResourceAccessPolicyService>;
