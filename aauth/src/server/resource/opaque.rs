use std::collections::HashMap;
use std::sync::Mutex;

use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};

pub trait OpaqueAccessStore: Send + Sync {
    fn issue(&self, agent_iss: &str) -> String;
    fn validate(&self, token: &str, agent_iss: &str) -> bool;
    fn revoke(&self, token: &str);
}

pub struct InMemoryOpaqueAccessStore {
    tokens: Mutex<HashMap<String, String>>,
}

impl InMemoryOpaqueAccessStore {
    pub fn new() -> Self {
        Self {
            tokens: Mutex::new(HashMap::new()),
        }
    }
}

impl Default for InMemoryOpaqueAccessStore {
    fn default() -> Self {
        Self::new()
    }
}

impl OpaqueAccessStore for InMemoryOpaqueAccessStore {
    fn issue(&self, agent_iss: &str) -> String {
        let token: String = (0..32)
            .map(|_| format!("{:02x}", rand::random::<u8>()))
            .collect();
        let encoded = URL_SAFE_NO_PAD.encode(token.as_bytes());
        self.tokens
            .lock()
            .unwrap()
            .insert(encoded.clone(), agent_iss.to_string());
        encoded
    }

    fn validate(&self, token: &str, agent_iss: &str) -> bool {
        self.tokens
            .lock()
            .unwrap()
            .get(token)
            .is_some_and(|iss| iss == agent_iss)
    }

    fn revoke(&self, token: &str) {
        self.tokens.lock().unwrap().remove(token);
    }
}
