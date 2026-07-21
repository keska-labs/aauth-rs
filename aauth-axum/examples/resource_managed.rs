//! Resource Managed access (two-party with interaction): opaque access tokens.

mod support;

use std::sync::Arc;

use aauth::protocol::AgentOkResponse;
use aauth_policy::{OpaqueAccessStore, PendingStore};

use support::{ServerConfig, build_client, spawn_test_server};

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let spawned = spawn_test_server(ServerConfig {
        resource_managed: true,
        ..Default::default()
    })
    .await;

    let resource_pending_cb = spawned.resource_pending.clone();
    let opaque_store_cb = spawned.opaque_store.clone();
    let agent_url = spawned.agent_url.clone();

    let on_interaction = Arc::new(move |_url: String, _code: String| {
        let pending = resource_pending_cb.clone();
        let opaque = opaque_store_cb.issue(&agent_url);
        let pending_id = resource_pending_cb.last_created.lock().unwrap().clone();
        tokio::spawn(async move {
            if let Some(id) = pending_id {
                let _ = pending
                    .complete(&id, aauth::PendingOutcome::OpaqueAccess(opaque))
                    .await;
            }
        });
    });

    let client = build_client(&spawned, None, None, Some(on_interaction), None, None);
    let response = client
        .get(format!("{}/api/data", spawned.resource_url))
        .send()
        .await?;

    println!("status: {}", response.status());
    let body: AgentOkResponse = response.json().await?;
    println!("agent: {}", body.agent);

    Ok(())
}
