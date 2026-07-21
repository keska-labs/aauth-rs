//! Reqwest client setup shared by integration tests and runnable examples.

use std::sync::Arc;

use aauth::KeyMaterialProvider;
use aauth_reqwest::{
    AgentMiddleware, AgentOptions, ClarificationCallback, ClientBuilder, InteractionCallback,
};

pub use super::AGENT_ID;
use super::axum_server::SpawnedServer;
use super::timeout::TEST_POLL_MAX_SECS;

pub fn build_client(
    spawned: &SpawnedServer,
    person_server_url: Option<String>,
    ps: Option<&str>,
    on_interaction: Option<InteractionCallback>,
    on_clarification: Option<ClarificationCallback>,
    provider: Option<std::sync::Arc<dyn KeyMaterialProvider>>,
) -> aauth_reqwest::ClientWithMiddleware {
    let agent_jwt = spawned
        .keys
        .mint_agent_jwt(&spawned.agent_url, AGENT_ID, ps);
    let provider = provider.unwrap_or_else(|| spawned.keys.key_provider(agent_jwt));

    let mut builder = AgentOptions::builder(provider)
        .max_poll_duration_secs(TEST_POLL_MAX_SECS)
        .metadata_fetcher(Arc::clone(&spawned.metadata_fetcher));
    if let Some(url) = person_server_url {
        builder = builder.person_server_url(url);
    }
    if let Some(on_interaction) = on_interaction {
        builder = builder.on_interaction(on_interaction);
    }
    if let Some(on_clarification) = on_clarification {
        builder = builder.on_clarification(on_clarification);
    }

    ClientBuilder::new(reqwest::Client::new())
        .with(AgentMiddleware::new(builder.build()))
        .build()
}
