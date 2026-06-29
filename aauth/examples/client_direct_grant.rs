//! Signed GET against a mock resource that returns an agent OK response.
//!
//! ```bash
//! cargo run --example client_direct_grant
//! ```

#[path = "shared/mock_resource.rs"]
mod mock_resource;

use std::sync::Arc;

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

    let client = mock_resource::build_client(
        Arc::clone(&provider),
        keys,
        RESOURCE_URL,
    );

    let response = client
        .get(format!("{RESOURCE_URL}/api/data"))
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
