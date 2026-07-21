//! Resource Managed access (two-party with interaction): opaque access tokens.

mod support;

use std::sync::Arc;

use aauth::ParsedToken;
use aauth::TestKeys;
use aauth::metadata::MetadataFetcher;
use aauth::protocol::{AgentOkResponse, JwksDocument, ResourceServerMetadata};
use aauth::resource::{ResourceAccessConfig, ResourceAccessMode};
use aauth_axum::{ResourceAuthLayer, ResourceServerState, VerifiedAAuthToken, resource_router};
use aauth_policy::{
    DeferInteractionResourcePolicy, InMemoryOpaqueAccessStore, InMemoryResourcePendingStore,
    OpaqueAccessStore, PendingStore, PolicyResourceAccessService,
};
use axum::Json;
use axum::Router;
use axum::extract::{FromRef, State};
use axum::routing::get;

use support::{
    AGENT_ID, AgentClientBuilder, MultiPartyMetadataFetcher, agent_issuer_app, bind_ephemeral,
    serve,
};

type ResourceService = PolicyResourceAccessService<
    DeferInteractionResourcePolicy,
    InMemoryResourcePendingStore,
    InMemoryOpaqueAccessStore,
>;

#[derive(Clone)]
struct ResourceState {
    resource: ResourceServerState<ResourceService>,
    discovery: DiscoveryState,
}

#[derive(Clone)]
struct DiscoveryState {
    resource_url: String,
    resource_jwks: JwksDocument,
}

impl FromRef<ResourceState> for ResourceServerState<ResourceService> {
    fn from_ref(input: &ResourceState) -> ResourceServerState<ResourceService> {
        input.resource.clone()
    }
}

impl FromRef<ResourceState> for DiscoveryState {
    fn from_ref(input: &ResourceState) -> DiscoveryState {
        input.discovery.clone()
    }
}

fn resource_managed_app(
    keys: &TestKeys,
    resource_url: &str,
    fetcher: Arc<dyn MetadataFetcher>,
    pending: InMemoryResourcePendingStore,
    opaque_store: InMemoryOpaqueAccessStore,
) -> Router {
    let service = PolicyResourceAccessService::new(
        DeferInteractionResourcePolicy {
            interaction_url: format!("{}/interact", resource_url.trim_end_matches('/')),
        },
        pending,
        opaque_store,
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

    let state = ResourceState {
        resource: ResourceServerState { service },
        discovery: DiscoveryState {
            resource_url: resource_url.to_string(),
            resource_jwks: JwksDocument {
                keys: keys.resource.jwk_set(),
            },
        },
    };

    Router::new()
        .route("/api/data", get(api_data))
        .route_layer(layer)
        .route("/.well-known/aauth-resource.json", get(resource_metadata))
        .route("/jwks", get(resource_jwks))
        .merge(resource_router::<ResourceState, _>())
        .with_state(state)
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let keys = TestKeys::generate();

    let (agent_listener, agent_url) = bind_ephemeral().await;
    let agent = serve(
        agent_listener,
        agent_issuer_app(&keys, &agent_url),
        agent_url,
    );

    let (resource_listener, resource_url) = bind_ephemeral().await;
    let pending = InMemoryResourcePendingStore::new();
    let opaque_store = InMemoryOpaqueAccessStore::new();
    let fetcher = MultiPartyMetadataFetcher::builder(&keys, &agent.url, &resource_url).build();

    let resource_pending_cb = pending.clone();
    let opaque_store_cb = opaque_store.clone();
    let resource = serve(
        resource_listener,
        resource_managed_app(
            &keys,
            &resource_url,
            Arc::clone(&fetcher),
            pending,
            opaque_store,
        ),
        resource_url,
    );

    let on_interaction = Arc::new(move |_url: String, _code: String| {
        let pending = resource_pending_cb.clone();
        let opaque = opaque_store_cb.issue(AGENT_ID);
        let pending_id = resource_pending_cb.last_created.lock().unwrap().clone();
        tokio::spawn(async move {
            if let Some(id) = pending_id {
                let _ = pending
                    .complete(&id, aauth::PendingOutcome::OpaqueAccess(opaque))
                    .await;
            }
        });
    });

    let client = AgentClientBuilder::new(&keys, &agent.url, fetcher)
        .on_interaction(on_interaction)
        .build();
    let response = client
        .get(format!("{}/api/data", resource.url))
        .send()
        .await?;

    println!("status: {}", response.status());
    let body: AgentOkResponse = response.json().await?;
    println!("agent: {}", body.agent);

    Ok(())
}

async fn api_data(token: VerifiedAAuthToken) -> Json<serde_json::Value> {
    match token.0 {
        ParsedToken::Agent(agent) => Json(serde_json::json!({
            "status": "ok",
            "agent": agent.identifier().to_string(),
        })),
        ParsedToken::Auth(auth) => Json(serde_json::json!({
            "status": "ok",
            "user": auth.sub,
        })),
        ParsedToken::Resource(_) => Json(serde_json::json!({
            "status": "error",
            "error": "unexpected_resource_token",
        })),
    }
}

async fn resource_metadata(State(state): State<DiscoveryState>) -> Json<ResourceServerMetadata> {
    Json(ResourceServerMetadata {
        issuer: Some(state.resource_url.clone()),
        jwks_uri: Some(format!("{}/jwks", state.resource_url.trim_end_matches('/'))),
        access_mode: None,
        name: Some("aauth-rs example resource".into()),
        description: None,
        logo_uri: None,
        logo_dark_uri: None,
        documentation_uri: None,
        tos_uri: None,
        policy_uri: None,
        authorization_endpoint: None,
        login_endpoint: None,
        scope_descriptions: None,
        signature_window: None,
        additional_signature_components: None,
        revocation_endpoint: None,
        r3_vocabularies: None,
    })
}

async fn resource_jwks(State(state): State<DiscoveryState>) -> Json<JwksDocument> {
    Json(state.resource_jwks.clone())
}
