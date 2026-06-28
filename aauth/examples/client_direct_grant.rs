//! Signed GET against a mock resource that returns an agent OK response.
//!
//! ```bash
//! cargo run --example client_direct_grant
//! ```

#[path = "shared/mock_resource.rs"]
mod mock_resource;

use aauth::client::{AAuthFetchOptions, create_aauth_fetch};
use aauth::http::HttpRequest;
use aauth::types::AgentOkResponse;
use aauth::{create_key_provider, create_test_keys, mint_agent_jwt};

const AGENT_URL: &str = "https://agent.example";
const AGENT_ID: &str = "aauth:test@example.com";
const RESOURCE_URL: &str = "https://resource.example";

#[tokio::main]
async fn main() -> aauth::Result<()> {
    let keys = create_test_keys();
    let agent_jwt = mint_agent_jwt(&keys, AGENT_URL, AGENT_ID);
    let provider = create_key_provider(&keys, agent_jwt);
    let client = mock_resource::MockResourceClient::new(keys, RESOURCE_URL);

    let fetch = create_aauth_fetch(AAuthFetchOptions {
        provider,
        client,
        auth_server_url: None,
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
    });

    let response = fetch
        .fetch(
            &format!("{RESOURCE_URL}/api/data"),
            HttpRequest {
                method: "GET".into(),
                url: format!("{RESOURCE_URL}/api/data"),
                headers: Default::default(),
                body: None,
            },
        )
        .await?;

    println!("status: {}", response.status);
    let body: AgentOkResponse = response.json()?;
    println!("agent: {}", body.agent);

    Ok(())
}
