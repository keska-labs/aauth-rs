//! Federated access (four-party): Person Server delegates to an Access Server.
//!
//! Matches the [Federated](https://explorer.aauth.dev/) flow. The resource token audience
//! is the Access Server; the Person Server federates the token exchange to the AS.

mod support;

use aauth::protocol::AuthOkResponse;

use support::{TestScenario, spawn_test_server};

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let spawned = spawn_test_server(TestScenario::federated()).await;

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
