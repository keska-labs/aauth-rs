//! Person Server Managed access (three-party): resource challenges for an auth token.
//!
//! Matches the [Person Server Managed](https://explorer.aauth.dev/) flow. The agent JWT
//! carries a `ps` claim; the resource returns 401, the client exchanges at the Person
//! Server, and retries with an auth token whose audience is the Person Server.

mod support;

use aauth::protocol::AuthOkResponse;

use support::{TestScenario, spawn_test_server};

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let spawned = spawn_test_server(TestScenario::person_managed()).await;

    let client = spawned.agent().with_spawned_person_server().build();
    let response = client
        .get(format!("{}/api/data", spawned.resource_url))
        .send()
        .await?;

    println!("status: {}", response.status());
    let body: AuthOkResponse = response.json().await?;
    println!("user: {:?}", body.user);

    Ok(())
}
