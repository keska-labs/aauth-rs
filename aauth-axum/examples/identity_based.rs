//! Identity Based access (two-party): agent JWT alone grants access.
//!
//! Matches the [Identity Based](https://explorer.aauth.dev/) flow.
//! `identity_resource_app` is the complete axum resource server: auth on the way
//! in via `ResourceAuthLayer`, then a normal handler that reads `VerifiedAAuthToken`.

mod support;

use std::sync::Arc;

use aauth::ParsedToken;
use aauth::metadata::MetadataFetcher;
use aauth::protocol::{AgentOkResponse, JwksDocument, ResourceServerMetadata};
use aauth::{NoResourceAccessService, ResourceAccessMode, TestKeys};
use aauth_axum::{ResourceAuthLayer, VerifiedAAuthToken};
use axum::Json;
use axum::Router;
use axum::extract::State;
use axum::routing::get;

use support::{
    AgentClientBuilder, MultiPartyMetadataFetcher, agent_issuer_app, bind_ephemeral, serve,
};

#[derive(Clone)]
struct ResourceState {
    resource_url: String,
    resource_jwks: JwksDocument,
}

/// Build the identity-based resource server app (ready to serve).
fn identity_resource_app(
    keys: &TestKeys,
    resource_url: &str,
    fetcher: Arc<dyn MetadataFetcher>,
) -> Router {
    let layer = ResourceAuthLayer::new(
        fetcher,
        resource_url.to_string(),
        ResourceAccessMode::<NoResourceAccessService>::IdentityBased,
        Arc::new(keys.resource_token_signer()),
    );

    let state = ResourceState {
        resource_url: resource_url.to_string(),
        resource_jwks: JwksDocument {
            keys: keys.resource.jwk_set(),
        },
    };

    // `route_layer` applies only to routes registered above it.
    Router::new()
        .route("/api/data", get(api_data))
        .route_layer(layer)
        .route("/.well-known/aauth-resource.json", get(resource_metadata))
        .route("/jwks", get(resource_jwks))
        .with_state(state)
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let keys = TestKeys::generate();

    // Demo agent issuer (separate process/origin in reality).
    let (agent_listener, agent_url) = bind_ephemeral().await;
    let agent = serve(
        agent_listener,
        agent_issuer_app(&keys, &agent_url),
        agent_url,
    );

    let (resource_listener, resource_url) = bind_ephemeral().await;
    let fetcher = MultiPartyMetadataFetcher::builder(&keys, &agent.url, &resource_url).build();
    let resource = serve(
        resource_listener,
        identity_resource_app(&keys, &resource_url, Arc::clone(&fetcher)),
        resource_url,
    );

    let client = AgentClientBuilder::new(&keys, &agent.url, fetcher).build();
    let response = client
        .get(format!("{}/api/data", resource.url))
        .send()
        .await?;

    println!("status: {}", response.status());
    let body: AgentOkResponse = response.json().await?;
    println!("agent: {}", body.agent);

    Ok(())
}

/// Runs only after `ResourceAuthLayer` has verified the signature and token.
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

async fn resource_metadata(State(state): State<ResourceState>) -> Json<ResourceServerMetadata> {
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

async fn resource_jwks(State(state): State<ResourceState>) -> Json<JwksDocument> {
    Json(state.resource_jwks.clone())
}
