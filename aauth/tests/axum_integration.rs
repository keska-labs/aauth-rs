//! Client + server integration tests over real HTTP (axum + reqwest).

mod support;

use aauth::client::reqwest::{AAuthClientOptions, AAuthMiddleware, ClientBuilder};

use aauth::types::{AgentOkResponse, AuthOkResponse};
use aauth::{create_key_provider, mint_agent_jwt};

use support::axum_server::{ServerConfig, SpawnedServer, spawn_test_server};

const AGENT_ID: &str = "aauth:test@example.com";

fn build_client(
    spawned: &SpawnedServer,
    auth_server_url: Option<String>,
) -> aauth::client::reqwest::ClientWithMiddleware {
    let agent_jwt = mint_agent_jwt(&spawned.keys, &spawned.agent_url, AGENT_ID);
    let provider = create_key_provider(&spawned.keys, agent_jwt);

    ClientBuilder::new(reqwest::Client::new())
        .with(AAuthMiddleware::new(AAuthClientOptions {
            provider,
            auth_server_url,
            auth_server_metadata: None,
            on_metadata: None,
            on_auth_token: None,
            on_opaque_token: None,
            opaque_token: None,
            on_interaction: None,
            on_clarification: None,
            justification: None,
            login_hint: None,
            tenant: None,
            domain_hint: None,
            capabilities: None,
            mission: None,
            prompt: None,
        }))
        .build()
}

#[tokio::test]
async fn direct_agent_grant_over_http() {
    let spawned = spawn_test_server(ServerConfig {
        require_auth_token: false,
        with_auth_routes: false,
    })
    .await;

    let client = build_client(&spawned, None);
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
async fn auth_token_challenge_over_http() {
    let spawned = spawn_test_server(ServerConfig {
        require_auth_token: true,
        with_auth_routes: true,
    })
    .await;

    let client = build_client(&spawned, Some(spawned.auth_server_url.clone()));
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
async fn unsigned_request_rejected_over_http() {
    let spawned = spawn_test_server(ServerConfig {
        require_auth_token: false,
        with_auth_routes: false,
    })
    .await;

    let response = reqwest::Client::new()
        .get(format!("{}/api/data", spawned.resource_url))
        .send()
        .await
        .expect("request");

    assert_eq!(response.status(), reqwest::StatusCode::UNAUTHORIZED);
}
