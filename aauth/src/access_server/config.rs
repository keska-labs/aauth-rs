use std::sync::Arc;

use crate::keys::TestKeys;
use crate::metadata::MetadataFetcher;

#[derive(Clone)]
pub struct AccessServerConfig {
    pub keys: TestKeys,
    pub access_server_url: String,
    pub resource_url: String,
    pub person_server_url: String,
    pub access_jwks_uri: String,
    pub pending_base_url: String,
    pub pending_path: String,
    pub pending_ttl_secs: u64,
    pub fetcher: Arc<dyn MetadataFetcher>,
}
