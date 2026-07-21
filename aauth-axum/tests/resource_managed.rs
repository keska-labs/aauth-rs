//! Resource-managed (two-party opaque access) mode.

mod support;

use std::sync::Arc;
use std::time::Duration;

use aauth::protocol::AgentOkResponse;
use aauth_policy::{OpaqueAccessStore, PendingStore};
use rstest::rstest;

use support::AGENT_ID;
use support::axum_server::{TestScenario, spawn_test_server};

#[rstest]
#[timeout(Duration::from_secs(1))]
#[tokio::test]
async fn resource_managed_over_http() {
    let spawned = spawn_test_server(TestScenario::resource_managed()).await;

    let resource_pending_cb = spawned.resource_pending.clone();
    let opaque_store_cb = spawned.opaque_store.clone();
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

    let client = spawned.agent().on_interaction(on_interaction).build();
    let response = client
        .get(format!("{}/api/data", spawned.resource_url))
        .send()
        .await
        .expect("request");

    assert!(response.status().is_success());
    let body: AgentOkResponse = response.json().await.expect("json");
    assert_eq!(body.status, "ok");
    assert_eq!(body.agent, AGENT_ID);
}
