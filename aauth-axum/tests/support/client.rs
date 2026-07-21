//! Reqwest client setup shared by integration tests and runnable examples.

use std::sync::Arc;

use aauth::KeyMaterialProvider;
use aauth_reqwest::{
    AgentMiddleware, AgentOptions, ClarificationCallback, ClientBuilder, InteractionCallback,
};

pub use super::AGENT_ID;
use super::axum_server::SpawnedServer;
use super::timeout::TEST_POLL_MAX_SECS;

/// Builder for an `aauth-reqwest` agent client pointed at a [`SpawnedServer`].
#[allow(dead_code)]
pub struct AgentClientBuilder<'a> {
    spawned: &'a SpawnedServer,
    person_server_url: Option<String>,
    agent_ps_claim: Option<String>,
    on_interaction: Option<InteractionCallback>,
    on_clarification: Option<ClarificationCallback>,
    provider: Option<Arc<dyn KeyMaterialProvider>>,
}

#[allow(dead_code)]
impl<'a> AgentClientBuilder<'a> {
    pub fn new(spawned: &'a SpawnedServer) -> Self {
        Self {
            spawned,
            person_server_url: None,
            agent_ps_claim: None,
            on_interaction: None,
            on_clarification: None,
            provider: None,
        }
    }

    /// Override the Person Server URL used for token exchange.
    pub fn person_server(mut self, url: impl Into<String>) -> Self {
        self.person_server_url = Some(url.into());
        self
    }

    /// Set the agent JWT `ps` claim (defaults to no claim when unset).
    pub fn agent_ps_claim(mut self, ps: impl Into<String>) -> Self {
        self.agent_ps_claim = Some(ps.into());
        self
    }

    /// Use the spawned Person Server for both exchange URL and agent `ps` claim.
    pub fn with_spawned_person_server(self) -> Self {
        let url = self.spawned.person_server_url.clone();
        self.person_server(url.clone()).agent_ps_claim(url)
    }

    pub fn on_interaction(mut self, cb: InteractionCallback) -> Self {
        self.on_interaction = Some(cb);
        self
    }

    pub fn on_clarification(mut self, cb: ClarificationCallback) -> Self {
        self.on_clarification = Some(cb);
        self
    }

    pub fn provider(mut self, provider: Arc<dyn KeyMaterialProvider>) -> Self {
        self.provider = Some(provider);
        self
    }

    pub fn build(self) -> aauth_reqwest::ClientWithMiddleware {
        let ps = self.agent_ps_claim.as_deref();
        let agent_jwt = self
            .spawned
            .keys
            .mint_agent_jwt(&self.spawned.agent_url, AGENT_ID, ps);
        let provider = self
            .provider
            .unwrap_or_else(|| self.spawned.keys.key_provider(agent_jwt));

        let mut builder = AgentOptions::builder(provider)
            .max_poll_duration_secs(TEST_POLL_MAX_SECS)
            .metadata_fetcher(Arc::clone(&self.spawned.metadata_fetcher));
        if let Some(url) = self.person_server_url {
            builder = builder.person_server_url(url);
        }
        if let Some(on_interaction) = self.on_interaction {
            builder = builder.on_interaction(on_interaction);
        }
        if let Some(on_clarification) = self.on_clarification {
            builder = builder.on_clarification(on_clarification);
        }

        ClientBuilder::new(reqwest::Client::new())
            .with(AgentMiddleware::new(builder.build()))
            .build()
    }
}

impl SpawnedServer {
    /// Start building an agent HTTP client for this server.
    pub fn agent(&self) -> AgentClientBuilder<'_> {
        AgentClientBuilder::new(self)
    }
}
