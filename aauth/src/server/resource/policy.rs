use crate::server::deferred::{InMemoryResourcePendingStore, PendingStore, ResourcePendingRecord};
use crate::server::policy::ResourceConsentPolicy;
use crate::server::resource::opaque::OpaqueAccessStore;

/// How a resource server evaluates access for incoming agent requests.
#[derive(Clone)]
pub enum ResourceAccessMode<P, S, O>
where
    P: ResourceConsentPolicy,
    S: PendingStore<ResourcePendingRecord>,
    O: OpaqueAccessStore + Clone,
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
    ResourceManaged {
        policy: P,
        pending: S,
        opaque: O,
        interaction_url: String,
        pending_base_url: String,
        pending_path: String,
        pending_ttl_secs: u64,
    },
}

/// Type-erased mode for callers that do not need resource-managed generics.
pub type ResourceAccessPolicy = ResourceAccessMode<
    crate::server::policy::AlwaysGrantResourcePolicy,
    InMemoryResourcePendingStore,
    crate::server::resource::InMemoryOpaqueAccessStore,
>;
