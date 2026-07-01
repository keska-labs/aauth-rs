//! Federated access (four-party): Person Server delegates to an Access Server.
//!
//! Matches the [Federated](https://explorer.aauth.dev/) flow. The resource token audience
//! is the Access Server; the Person Server federates the token exchange to the AS.

mod support;

use aauth::protocol::AuthOkResponse;

use support::{ServerConfig, build_client, spawn_test_server};

#[tokio::main]
async fn main() -> aauth::Result<()> {
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
        .map_err(|e| aauth::AAuthError::Message(e.to_string()))?;

    println!("status: {}", response.status());
    let body: AuthOkResponse = response
        .json()
        .await
        .map_err(|e| aauth::AAuthError::Message(e.to_string()))?;
    println!("user: {:?}", body.user);

    Ok(())
}
