use std::sync::{Arc, Mutex};

use aauth::InMemoryPendingStore;
use aauth::types::TokenExchangeRequest;

use aauth::TestKeys;

use super::mock_transport::{MockServerState, MockTransport};

pub struct MockServerConfig {
    pub keys: TestKeys,
    pub resource_url: String,
    pub person_server_url: String,
    pub agent_url: String,
    pub sub: String,
    pub require_auth_token: bool,
    pub deferred_mode: bool,
    pub pending: Option<InMemoryPendingStore>,
    pub on_token_request: Option<Arc<Mutex<Option<TokenExchangeRequest>>>>,
}

pub struct MockServer {
    pub state: Arc<MockServerState>,
}

impl MockServer {
    pub fn new(config: MockServerConfig) -> Self {
        let pending = config.pending.unwrap_or_else(InMemoryPendingStore::new);

        let state = Arc::new(MockServerState {
            keys: config.keys,
            resource_url: config.resource_url,
            person_server_url: config.person_server_url,
            agent_url: config.agent_url,
            require_auth_token: config.require_auth_token,
            deferred_mode: config.deferred_mode,
            pending,
            on_token_request: config.on_token_request,
        });

        Self { state }
    }

    pub fn mock_transport(&self) -> MockTransport {
        MockTransport::new(Arc::clone(&self.state))
    }

    pub fn pending_store(&self) -> InMemoryPendingStore {
        self.state.pending.clone()
    }
}
