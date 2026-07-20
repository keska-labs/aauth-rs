use std::sync::Arc;

use crate::keys::TestKeys;
use crate::metadata::MetadataFetcher;

#[derive(Clone)]
pub struct PersonServerConfig {
    pub keys: TestKeys,
    pub person_server_url: String,
    pub resource_url: String,
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
    pub fn person_server_signing_jwk(&self) -> crate::jwt::OkpSigningJwk {
        self.keys.person_server.signing_jwk()
    }
}
