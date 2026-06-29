use std::collections::HashMap;
use std::sync::{Arc, Mutex};

use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};

pub trait OpaqueAccessStore: Send + Sync {
    fn issue(&self, agent_id: &str) -> String;
    fn validate(&self, token: &str, agent_id: &str) -> bool;
    fn revoke(&self, token: &str);
}

#[derive(Clone)]
pub struct InMemoryOpaqueAccessStore {
    tokens: Arc<Mutex<HashMap<String, String>>>,
}

impl InMemoryOpaqueAccessStore {
    pub fn new() -> Self {
        Self {
            tokens: Arc::new(Mutex::new(HashMap::new())),
        }
    }
}

impl Default for InMemoryOpaqueAccessStore {
    fn default() -> Self {
        Self::new()
    }
}

impl OpaqueAccessStore for InMemoryOpaqueAccessStore {
    fn issue(&self, agent_id: &str) -> String {
        let token: String = (0..32)
            .map(|_| format!("{:02x}", rand::random::<u8>()))
            .collect();
        let encoded = URL_SAFE_NO_PAD.encode(token.as_bytes());
        self.tokens
            .lock()
            .unwrap()
            .insert(encoded.clone(), agent_id.to_string());
        encoded
    }

    fn validate(&self, token: &str, agent_id: &str) -> bool {
        self.tokens
            .lock()
            .unwrap()
            .get(token)
            .is_some_and(|id| id == agent_id)
    }

    fn revoke(&self, token: &str) {
        self.tokens.lock().unwrap().remove(token);
    }
}
