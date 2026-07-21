//! Identity-based access mode (agent JWT alone).

mod support;

use std::time::Duration;

use aauth::TestKeys;
use aauth::protocol::AgentOkResponse;
use rstest::rstest;

use support::AGENT_ID;
use support::axum_server::{TestScenario, spawn_test_server};

#[rstest]
#[timeout(Duration::from_secs(1))]
#[tokio::test]
async fn identity_based_over_http() {
    let spawned = spawn_test_server(TestScenario::identity_based()).await;

    let client = spawned.agent().build();
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

#[rstest]
#[timeout(Duration::from_secs(1))]
#[tokio::test]
async fn unsigned_request_rejected_over_http() {
    let spawned = spawn_test_server(TestScenario::identity_based()).await;

    let response = reqwest::Client::new()
        .get(format!("{}/api/data", spawned.resource_url))
        .send()
        .await
        .expect("request");

    assert_eq!(response.status(), reqwest::StatusCode::UNAUTHORIZED);
}

#[rstest]
#[timeout(Duration::from_secs(1))]
#[tokio::test]
async fn invalid_signature_rejected_over_http() {
    let spawned = spawn_test_server(TestScenario::identity_based()).await;

    let wrong_keys = TestKeys::generate();
    let agent_jwt = wrong_keys.mint_agent_jwt(
        &spawned.agent_url,
        AGENT_ID,
        Some(&spawned.person_server_url),
    );
    let provider = wrong_keys.key_provider(agent_jwt);

    let client = spawned.agent().provider(provider).build();
    let response = client
        .get(format!("{}/api/data", spawned.resource_url))
        .send()
        .await
        .expect("request");

    assert_eq!(response.status(), reqwest::StatusCode::UNAUTHORIZED);
}
