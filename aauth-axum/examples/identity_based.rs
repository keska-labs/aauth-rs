//! Identity Based access (two-party): agent JWT alone grants access.
//!
//! Matches the [Identity Based](https://explorer.aauth.dev/) flow on the AAuth explorer.
//! The resource server verifies the agent signature and accepts the agent token without
//! a Person Server or Access Server challenge.

mod support;

use aauth::protocol::AgentOkResponse;

use support::{TestScenario, spawn_test_server};

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let spawned = spawn_test_server(TestScenario::identity_based()).await;

    let client = spawned.agent().build();
    let response = client
        .get(format!("{}/api/data", spawned.resource_url))
        .send()
        .await?;

    println!("status: {}", response.status());
    let body: AgentOkResponse = response.json().await?;
    println!("agent: {}", body.agent);

    Ok(())
}
