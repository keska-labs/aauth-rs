//! E2E tests mirroring each runnable example (`cargo run --example <name>`).

mod support;

use std::sync::Arc;
use std::time::Duration;

use aauth::types::{AgentOkResponse, AuthOkResponse};
use aauth::{OpaqueAccessStore, PendingStore};
use rstest::rstest;

use support::axum_server::{ServerConfig, spawn_test_server};
use support::client::build_client;

#[rstest]
#[timeout(Duration::from_secs(1))]
#[tokio::test]
async fn identity_based_over_http() {
    let spawned = spawn_test_server(ServerConfig {
        require_auth_token: false,
        with_auth_routes: false,
        ..Default::default()
    })
    .await;

    let client = build_client(&spawned, None, None, None, None, None);
    let response = client
        .get(format!("{}/api/data", spawned.resource_url))
        .send()
        .await
        .expect("request");

    assert!(response.status().is_success());
    let body: AgentOkResponse = response.json().await.expect("json");
    assert_eq!(body.status, "ok");
    assert_eq!(body.agent, spawned.agent_url);
}

#[rstest]
#[timeout(Duration::from_secs(1))]
#[tokio::test]
async fn person_server_managed_over_http() {
    let spawned = spawn_test_server(ServerConfig {
        require_auth_token: true,
        with_auth_routes: true,
        ..Default::default()
    })
    .await;

    let client = build_client(
        &spawned,
        Some(spawned.person_server_url.clone()),
        Some(&spawned.person_server_url),
        None,
        None,
        None,
    );
    let response = client
        .get(format!("{}/api/data", spawned.resource_url))
        .send()
        .await
        .expect("request");

    assert!(response.status().is_success());
    let body: AuthOkResponse = response.json().await.expect("json");
    assert_eq!(body.status, "ok");
    assert_eq!(body.user.as_deref(), Some("user-123"));
}

#[rstest]
#[timeout(Duration::from_secs(1))]
#[tokio::test]
async fn resource_managed_over_http() {
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
        .await
        .expect("request");

    assert!(response.status().is_success());
    let body: AgentOkResponse = response.json().await.expect("json");
    assert_eq!(body.status, "ok");
    assert_eq!(body.agent, spawned.agent_url);
}

#[rstest]
#[timeout(Duration::from_secs(1))]
#[tokio::test]
async fn federated_over_http() {
    let spawned = spawn_test_server(ServerConfig {
        require_auth_token: true,
        with_auth_routes: true,
        federated: true,
        ..Default::default()
    })
    .await;

    let client = build_client(
        &spawned,
        Some(spawned.person_server_url.clone()),
        Some(&spawned.person_server_url),
        None,
        None,
        None,
    );
    let response = client
        .get(format!("{}/api/data", spawned.resource_url))
        .send()
        .await
        .expect("request");

    assert!(response.status().is_success());
    let body: AuthOkResponse = response.json().await.expect("json");
    assert_eq!(body.status, "ok");
    assert_eq!(body.user.as_deref(), Some("user-federated"));
}
