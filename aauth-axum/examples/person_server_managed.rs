//! Person Server Managed access (three-party): resource challenges for an auth token.
//!
//! Matches the [Person Server Managed](https://explorer.aauth.dev/) flow. The agent JWT
//! carries a `ps` claim; the resource returns 401, the client exchanges at the Person
//! Server, and retries with an auth token whose audience is the Person Server.

mod support;

use aauth::protocol::AuthOkResponse;

use support::{ServerConfig, build_client, spawn_test_server};

#[tokio::main]
async fn main() -> aauth::Result<()> {
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
        .map_err(|e| aauth::AAuthError::Message(e.to_string()))?;

    println!("status: {}", response.status());
    let body: AuthOkResponse = response
        .json()
        .await
        .map_err(|e| aauth::AAuthError::Message(e.to_string()))?;
    println!("user: {:?}", body.user);

    Ok(())
}
