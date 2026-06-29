//! E2E tests mirroring each runnable example (`cargo run --example <name>`).
//!
//! | Explorer flow           | Example                   | Test                            |
//! |-------------------------|---------------------------|---------------------------------|
//! | Identity Based          | `identity_based`          | `identity_based_over_http`      |
//! | Person Server Managed   | `person_server_managed`   | `person_server_managed_over_http` |
//! | Resource Managed        | `resource_managed`        | `resource_managed_over_http`    |
//! | Federated               | `federated`               | `federated_over_http`           |

mod support;

use std::sync::Arc;

use aauth::types::{AgentOkResponse, AuthOkResponse};
use aauth::{InMemoryOpaqueAccessStore, OpaqueAccessStore};

use support::axum_server::{ServerConfig, spawn_test_server};
use support::client::build_client;

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

#[tokio::test]
async fn resource_managed_over_http() {
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
        .expect("request");

    assert!(response.status().is_success());
    let body: AgentOkResponse = response.json().await.expect("json");
    assert_eq!(body.status, "ok");
    assert_eq!(body.agent, spawned.agent_url);
}

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
