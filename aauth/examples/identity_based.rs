//! Identity Based access (two-party): agent JWT alone grants access.
//!
//! Matches the [Identity Based](https://explorer.aauth.dev/) flow on the AAuth explorer.
//! The resource server verifies the agent signature and accepts the agent token without
//! a Person Server or Access Server challenge.

mod support;

use aauth::types::AgentOkResponse;

use support::{ServerConfig, build_client, spawn_test_server};

#[tokio::main]
async fn main() -> aauth::Result<()> {
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
        .map_err(|e| aauth::AAuthError::Message(e.to_string()))?;

    println!("status: {}", response.status());
    let body: AgentOkResponse = response
        .json()
        .await
        .map_err(|e| aauth::AAuthError::Message(e.to_string()))?;
    println!("agent: {}", body.agent);

    Ok(())
}
