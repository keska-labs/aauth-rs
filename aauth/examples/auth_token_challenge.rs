//! Full 401 auth-token challenge: resource server requires auth token, client exchanges.
//!
//! ```bash
//! cargo run --example auth_token_challenge
//! ```

#[path = "../tests/support/axum_server.rs"]
mod server;

use aauth::client::reqwest::{AAuthClientOptions, AAuthMiddleware, ClientBuilder};
use aauth::types::AuthOkResponse;
use aauth::{create_key_provider, mint_agent_jwt};

const AGENT_ID: &str = "aauth:test@example.com";

#[tokio::main]
async fn main() -> aauth::Result<()> {
    let spawned = server::spawn_test_server(server::ServerConfig {
        require_auth_token: true,
        with_auth_routes: true,
        ..Default::default()
    })
    .await;

    let agent_jwt = mint_agent_jwt(&spawned.keys, &spawned.agent_url, AGENT_ID);
    let provider = create_key_provider(&spawned.keys, agent_jwt);

    let client = ClientBuilder::new(reqwest::Client::new())
        .with(AAuthMiddleware::new(AAuthClientOptions {
            provider,
            person_server_url: Some(spawned.person_server_url.clone()),
            person_server_metadata: None,
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
        .build();

    let response = client
        .get(format!("{}/api/data", spawned.resource_url))
        .send()
        .await
        .map_err(|e| aauth::AAuthError::Message(e.to_string()))?;

    assert!(
        response.status().is_success(),
        "expected 200 OK after token exchange"
    );
    let body: AuthOkResponse = response
        .json()
        .await
        .map_err(|e| aauth::AAuthError::Message(e.to_string()))?;
    println!("status: ok, user: {:?}", body.user);

    Ok(())
}
