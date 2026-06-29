//! Resource Managed access (two-party with interaction): opaque access tokens.
//!
//! Matches the [Resource Managed](https://explorer.aauth.dev/) flow. The resource server
//! owns the interaction and issues opaque `AAuth-Access` tokens after user consent.

mod support;

use std::sync::Arc;

use aauth::types::AgentOkResponse;
use aauth::{InMemoryOpaqueAccessStore, OpaqueAccessStore};

use support::{build_client, spawn_test_server, ServerConfig};

#[tokio::main]
async fn main() -> aauth::Result<()> {
    let spawned = spawn_test_server(ServerConfig {
        resource_managed: true,
        ..Default::default()
    })
    .await;

    let manager_cb = Arc::clone(&spawned.resource_interaction_manager);
    let opaque_store_cb: Arc<InMemoryOpaqueAccessStore> = Arc::clone(&spawned.opaque_store);
    let pending_id_capture_cb = Arc::clone(&spawned.resource_pending_id_capture);
    let agent_url = spawned.agent_url.clone();

    let on_interaction = Arc::new(move |_url: String, _code: String| {
        if let Some(id) = pending_id_capture_cb.lock().unwrap().clone() {
            let opaque = opaque_store_cb.issue(&agent_url);
            let _ = manager_cb.resolve_opaque_access(&id, opaque);
        }
    });

    let client = build_client(&spawned, None, None, Some(on_interaction), None, None);
    let response = client
        .get(format!("{}/api/data", spawned.resource_url))
        .send()
        .await
        .map_err(|e| aauth::AAuthError::Message(e.to_string()))?;

    println!("status: {}", response.status());
    let body: AgentOkResponse = response
        .json()
        .await
        .map_err(|e| aauth::AAuthError::Message(e.to_string()))?;
    println!("agent: {}", body.agent);

    Ok(())
}
