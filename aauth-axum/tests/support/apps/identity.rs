//! Identity-based resource server app definer.

use std::sync::Arc;

use crate::support::metadata::MultiPartyMetadataFetcher;
use aauth::TestKeys;
use aauth::{NoResourceAccessService, ResourceAccessMode};
use aauth_axum::ResourceAuthLayer;
use axum::Router;
use axum::routing::get;

use super::common::{ResourceDiscoveryState, api_data, resource_jwks, resource_metadata};

/// Build the identity-based resource server app (ready to serve).
pub fn identity_resource_app(
    keys: &TestKeys,
    resource_url: &str,
    fetcher: Arc<MultiPartyMetadataFetcher>,
) -> Router {
    let layer = ResourceAuthLayer::new(
        fetcher,
        resource_url.to_string(),
        ResourceAccessMode::<NoResourceAccessService>::IdentityBased,
        Arc::new(keys.resource_token_signer()),
    );

    let state = ResourceDiscoveryState::from_keys(keys, resource_url)
        .with_access_mode(aauth::protocol::ResourceAccessModeWire::AgentToken);

    // `route_layer` applies only to routes registered above it.
    Router::new()
        .route("/api/data", get(api_data))
        .route_layer(layer)
        .route("/.well-known/aauth-resource.json", get(resource_metadata))
        .route("/jwks", get(resource_jwks))
        .with_state(state)
}
