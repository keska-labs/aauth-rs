use std::sync::{Arc, Mutex};

use aauth::server::{InteractionManager, InteractionManagerOptions};
use aauth::types::TokenExchangeRequest;

use aauth::TestKeys;

use super::mock_transport::{MockServerState, MockTransport};

pub struct MockServerConfig {
    pub keys: TestKeys,
    pub resource_url: String,
    pub auth_server_url: String,
    pub agent_url: String,
    pub sub: String,
    pub require_auth_token: bool,
    pub deferred_mode: bool,
    pub interaction_manager: Option<Arc<InteractionManager>>,
    pub on_token_request: Option<Arc<Mutex<Option<TokenExchangeRequest>>>>,
    pub pending_id_capture: Option<Arc<Mutex<Option<String>>>>,
}

pub struct MockServer {
    pub state: Arc<MockServerState>,
}

impl MockServer {
    pub fn new(config: MockServerConfig) -> Self {
        let interaction_manager = Arc::new(Mutex::new(config.interaction_manager.or_else(|| {
            if config.deferred_mode {
                Some(Arc::new(InteractionManager::new(
                    InteractionManagerOptions {
                        base_url: config.auth_server_url.clone(),
                        interaction_url: format!("{}/interact", config.auth_server_url),
                        pending_path: None,
                        ttl: None,
                    },
                )))
            } else {
                None
            }
        })));

        let state = Arc::new(MockServerState {
            keys: config.keys,
            resource_url: config.resource_url,
            auth_server_url: config.auth_server_url,
            agent_url: config.agent_url,
            require_auth_token: config.require_auth_token,
            deferred_mode: config.deferred_mode,
            interaction_manager,
            on_token_request: config.on_token_request,
            pending_id_capture: config.pending_id_capture,
        });

        Self { state }
    }

    pub fn mock_transport(&self) -> MockTransport {
        MockTransport::new(Arc::clone(&self.state))
    }

    pub fn interaction_manager(&self) -> Option<Arc<InteractionManager>> {
        self.state.interaction_manager.lock().unwrap().clone()
    }
}
