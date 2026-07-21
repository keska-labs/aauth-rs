//! Reqwest agent client builder for integration tests and examples.

use std::sync::Arc;

use aauth::StaticKeyMaterialProvider;
use aauth::TestKeys;
use aauth_reqwest::{
    AgentMiddleware, AgentOptions, ClarificationCallback, ClientBuilder, InteractionCallback,
};

use super::AGENT_ID;
use super::metadata::MultiPartyMetadataFetcher;
use super::timeout::TEST_POLL_MAX_SECS;

/// Builder for an `aauth-reqwest` agent client.
pub struct AgentClientBuilder {
    keys: TestKeys,
    agent_url: String,
    metadata_fetcher: Arc<MultiPartyMetadataFetcher>,
    person_server_url: Option<String>,
    agent_ps_claim: Option<String>,
    on_interaction: Option<InteractionCallback>,
    on_clarification: Option<ClarificationCallback>,
    provider: Option<Arc<StaticKeyMaterialProvider>>,
}

impl AgentClientBuilder {
    pub fn new(
        keys: &TestKeys,
        agent_url: impl Into<String>,
        metadata_fetcher: Arc<MultiPartyMetadataFetcher>,
    ) -> Self {
        Self {
            keys: keys.clone(),
            agent_url: agent_url.into(),
            metadata_fetcher,
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

    /// Use `url` for both token exchange and the agent JWT `ps` claim.
    pub fn with_person_server(self, url: impl Into<String>) -> Self {
        let url = url.into();
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

    pub fn provider(mut self, provider: Arc<StaticKeyMaterialProvider>) -> Self {
        self.provider = Some(provider);
        self
    }

    pub fn build(self) -> aauth_reqwest::ClientWithMiddleware {
        let ps = self.agent_ps_claim.as_deref();
        let agent_jwt = self.keys.mint_agent_jwt(&self.agent_url, AGENT_ID, ps);
        let provider = self
            .provider
            .unwrap_or_else(|| self.keys.key_provider(agent_jwt));

        let mut builder = AgentOptions::builder(provider)
            .max_poll_duration_secs(TEST_POLL_MAX_SECS)
            .metadata_fetcher(self.metadata_fetcher);
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
