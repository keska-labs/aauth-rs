//! Identity Based access (two-party): agent JWT alone grants access.
//!
//! Matches the [Identity Based](https://explorer.aauth.dev/) flow on the AAuth explorer.
//! The resource server verifies the agent signature and accepts the agent token without
//! a Person Server or Access Server challenge.

mod support;

use aauth::protocol::AgentOkResponse;

use support::{ServerConfig, build_client, spawn_test_server};

#[tokio::main]
async fn main() -> anyhow::Result<()> {
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
        .await?;

    println!("status: {}", response.status());
    let body: AgentOkResponse = response.json().await?;
    println!("agent: {}", body.agent);

    Ok(())
}
