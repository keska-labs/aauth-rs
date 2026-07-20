use std::sync::Arc;

use crate::keys::TestKeys;
use crate::metadata::MetadataFetcher;
use crate::person_server::orchestrate::PersonOrchestrateConfig;

#[derive(Clone)]
pub struct PersonServerConfig {
    pub keys: TestKeys,
    pub person_server_url: String,
    pub resource_url: String,
    pub agent_url: String,
    pub person_jwks_uri: String,
    pub interaction_url: String,
    pub pending_base_url: String,
    pub pending_path: String,
    pub pending_ttl_secs: u64,
    pub fetcher: Arc<dyn MetadataFetcher>,
    pub http_client: reqwest::Client,
    /// Max seconds for federation pending polls (default 300).
    pub federation_poll_max_secs: Option<u64>,
}

impl PersonServerConfig {
    pub fn orchestrate(&self) -> PersonOrchestrateConfig {
        PersonOrchestrateConfig {
            person_server_url: self.person_server_url.clone(),
            resource_url: self.resource_url.clone(),
            interaction_url: self.interaction_url.clone(),
            pending_base_url: self.pending_base_url.clone(),
            pending_path: self.pending_path.clone(),
            pending_ttl_secs: self.pending_ttl_secs,
            fetcher: Arc::clone(&self.fetcher),
            http_client: self.http_client.clone(),
            federation: crate::person_server::federation::FederationConfig {
                fetcher: Arc::clone(&self.fetcher),
            },
            federation_poll_max_secs: self.federation_poll_max_secs,
            keys: self.keys.clone(),
            person_server_signing_jwk: self.keys.person_server.signing_jwk(),
        }
    }
}
