//! Resource-managed (opaque access) app definer.

use std::sync::Arc;

use crate::support::metadata::MultiPartyMetadataFetcher;
use aauth::TestKeys;
use aauth::resource::{ResourceAccessConfig, ResourceAccessMode};
use aauth_axum::{ResourceAuthLayer, ResourceServerState, resource_router};
use aauth_policy::{
    AlwaysGrantResourcePolicy, DeferInteractionResourcePolicy, InMemoryOpaqueAccessStore,
    InMemoryResourcePendingStore, PolicyResourceAccessService, ResourceConsentPolicy,
};
use axum::Router;
use axum::extract::FromRef;
use axum::routing::get;

use super::common::{ResourceDiscoveryState, api_data, resource_jwks, resource_metadata};

/// Pending / grant behaviour for resource-managed consent.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum ResourcePolicyKind {
    Grant,
    #[default]
    Interaction,
}

#[derive(Clone)]
enum ResourcePolicy {
    Grant(AlwaysGrantResourcePolicy),
    Defer(DeferInteractionResourcePolicy),
}

#[async_trait::async_trait]
impl ResourceConsentPolicy for ResourcePolicy {
    async fn evaluate(
        &self,
        ctx: &aauth::ResourceAccessContext,
    ) -> Result<aauth_policy::ResourceConsentDecision, aauth_policy::PolicyError> {
        match self {
            Self::Grant(p) => p.evaluate(ctx).await,
            Self::Defer(p) => p.evaluate(ctx).await,
        }
    }

    async fn resume(
        &self,
        ctx: &aauth::ResourceAccessContext,
        input: aauth::PendingInput,
    ) -> Result<aauth_policy::ResourceConsentDecision, aauth_policy::PolicyError> {
        match self {
            Self::Grant(p) => p.resume(ctx, input).await,
            Self::Defer(p) => p.resume(ctx, input).await,
        }
    }
}

type ResourceService = PolicyResourceAccessService<
    ResourcePolicy,
    InMemoryResourcePendingStore,
    InMemoryOpaqueAccessStore,
>;

#[derive(Clone)]
struct ResourceManagedState {
    resource: ResourceServerState<ResourceService>,
    discovery: ResourceDiscoveryState,
}

impl FromRef<ResourceManagedState> for ResourceServerState<ResourceService> {
    fn from_ref(input: &ResourceManagedState) -> ResourceServerState<ResourceService> {
        input.resource.clone()
    }
}

impl FromRef<ResourceManagedState> for ResourceDiscoveryState {
    fn from_ref(input: &ResourceManagedState) -> ResourceDiscoveryState {
        input.discovery.clone()
    }
}

/// Parts returned by [`resource_managed_app`].
pub struct ResourceManagedParts {
    pub app: Router,
    pub pending: InMemoryResourcePendingStore,
    pub opaque_store: InMemoryOpaqueAccessStore,
}

/// Build a resource-managed resource server app.
pub fn resource_managed_app(
    keys: &TestKeys,
    resource_url: &str,
    fetcher: Arc<MultiPartyMetadataFetcher>,
    policy_kind: ResourcePolicyKind,
) -> ResourceManagedParts {
    let pending = InMemoryResourcePendingStore::new();
    let opaque_store = InMemoryOpaqueAccessStore::new();

    let policy = match policy_kind {
        ResourcePolicyKind::Interaction => ResourcePolicy::Defer(DeferInteractionResourcePolicy {
            interaction_url: format!("{}/interact", resource_url.trim_end_matches('/')),
        }),
        ResourcePolicyKind::Grant => ResourcePolicy::Grant(AlwaysGrantResourcePolicy),
    };

    let service = PolicyResourceAccessService::new(
        policy,
        pending.clone(),
        opaque_store.clone(),
        ResourceAccessConfig {
            interaction_url: format!("{}/interact", resource_url.trim_end_matches('/')),
            pending_base_url: resource_url.to_string(),
            pending_path: "/resource/pending".into(),
            pending_ttl_secs: aauth::DEFAULT_PENDING_TTL_SECS,
        },
    );

    let layer = ResourceAuthLayer::new(
        fetcher,
        resource_url.to_string(),
        ResourceAccessMode::ResourceManaged {
            service: service.clone(),
        },
        Arc::new(keys.resource_token_signer()),
    );

    let state = ResourceManagedState {
        resource: ResourceServerState { service },
        discovery: ResourceDiscoveryState::from_keys(keys, resource_url),
    };

    let app = Router::new()
        .route("/api/data", get(api_data))
        .route_layer(layer)
        .route("/.well-known/aauth-resource.json", get(resource_metadata))
        .route("/jwks", get(resource_jwks))
        .merge(resource_router::<ResourceManagedState, _>())
        .with_state(state);

    ResourceManagedParts {
        app,
        pending,
        opaque_store,
    }
}
