//! Reqwest client setup shared by integration tests and runnable examples.

use aauth::client::reqwest::{
    AAuthClientOptions, AAuthMiddleware, ClarificationCallback, ClientBuilder, InteractionCallback,
};
use aauth::{KeyMaterialProvider, create_key_provider, mint_agent_jwt};

use super::axum_server::SpawnedServer;
use super::timeout::TEST_POLL_MAX_SECS;

pub const AGENT_ID: &str = "aauth:test@example.com";

pub fn build_client(
    spawned: &SpawnedServer,
    person_server_url: Option<String>,
    ps: Option<&str>,
    on_interaction: Option<InteractionCallback>,
    on_clarification: Option<ClarificationCallback>,
    provider: Option<std::sync::Arc<dyn KeyMaterialProvider>>,
) -> aauth::client::reqwest::ClientWithMiddleware {
    let agent_jwt = mint_agent_jwt(&spawned.keys, &spawned.agent_url, AGENT_ID, ps);
    let provider = provider.unwrap_or_else(|| create_key_provider(&spawned.keys, agent_jwt));

    ClientBuilder::new(reqwest::Client::new())
        .with(AAuthMiddleware::new(AAuthClientOptions {
            provider,
            person_server_url,
            person_server_metadata: None,
            on_metadata: None,
            on_auth_token: None,
            on_opaque_token: None,
            opaque_token: None,
            on_interaction,
            on_clarification,
            justification: None,
            login_hint: None,
            tenant: None,
            domain_hint: None,
            capabilities: None,
            mission: None,
            prompt: None,
            max_poll_duration_secs: Some(TEST_POLL_MAX_SECS),
        }))
        .build()
}
