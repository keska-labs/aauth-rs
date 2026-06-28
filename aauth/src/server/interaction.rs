use std::collections::HashMap;
use std::sync::{Arc, Mutex};
use std::time::{SystemTime, UNIX_EPOCH};

use serde_json::Value;

use crate::headers::{build_aauth_requirement, AAuthRequirementParams};
use crate::interaction_code::generate_code;
use crate::types::RequirementLevel;

#[derive(Debug, Clone)]
pub struct PendingRequest<T = Value> {
    pub id: String,
    pub code: String,
    pub created_at: u64,
    pub result: Arc<Mutex<Option<Result<T, String>>>>,
}

#[derive(Debug, Clone)]
pub struct InteractionManagerOptions {
    pub base_url: String,
    pub interaction_url: String,
    pub pending_path: Option<String>,
    pub ttl: Option<u64>,
}

pub struct InteractionManager {
    pending: Mutex<HashMap<String, PendingRequest<Value>>>,
    base_url: String,
    interaction_url: String,
    pending_path: String,
    ttl: u64,
}

impl InteractionManager {
    pub fn new(options: InteractionManagerOptions) -> Self {
        Self {
            pending: Mutex::new(HashMap::new()),
            base_url: options.base_url.trim_end_matches('/').to_string(),
            interaction_url: options.interaction_url.trim_end_matches('/').to_string(),
            pending_path: options
                .pending_path
                .unwrap_or_else(|| "/pending".to_string()),
            ttl: options.ttl.unwrap_or(600),
        }
    }

    pub fn create_pending(&self) -> (HashMap<String, String>, PendingRequest<Value>) {
        let id: String = (0..16)
            .map(|_| format!("{:02x}", rand::random::<u8>()))
            .collect();
        let code = generate_code();
        let created_at = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs();

        let pending = PendingRequest {
            id: id.clone(),
            code: code.clone(),
            created_at,
            result: Arc::new(Mutex::new(None)),
        };

        self.pending
            .lock()
            .unwrap()
            .insert(id.clone(), pending.clone());

        let location = format!("{}{}/{}", self.base_url, self.pending_path, id);
        let aauth_requirement = build_aauth_requirement(
            RequirementLevel::Interaction,
            Some(&AAuthRequirementParams {
                url: Some(&self.interaction_url),
                code: Some(&code),
                ..Default::default()
            }),
        )
        .expect("valid interaction header");

        let headers = HashMap::from([
            ("Location".to_string(), location),
            ("Retry-After".to_string(), "0".to_string()),
            ("Cache-Control".to_string(), "no-store".to_string()),
            ("AAuth-Requirement".to_string(), aauth_requirement),
        ]);

        (headers, pending)
    }

    pub fn get_pending(&self, id: &str) -> Option<PendingRequest<Value>> {
        self.pending.lock().unwrap().get(id).cloned()
    }

    pub fn resolve(&self, id: &str, value: Value) -> Result<(), String> {
        let pending = self
            .pending
            .lock()
            .unwrap()
            .get(id)
            .cloned()
            .ok_or_else(|| format!("No pending request with id: {id}"))?;
        *pending.result.lock().unwrap() = Some(Ok(value));
        Ok(())
    }

    pub fn reject(&self, id: &str, error: impl Into<String>) -> Result<(), String> {
        let pending = self
            .pending
            .lock()
            .unwrap()
            .get(id)
            .cloned()
            .ok_or_else(|| format!("No pending request with id: {id}"))?;
        *pending.result.lock().unwrap() = Some(Err(error.into()));
        Ok(())
    }

    pub fn remove(&self, id: &str) {
        self.pending.lock().unwrap().remove(id);
    }

    pub fn cleanup(&self) {
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs();
        let ttl = self.ttl;
        self.pending.lock().unwrap().retain(|_, pending| {
            if now.saturating_sub(pending.created_at) > ttl {
                *pending.result.lock().unwrap() = Some(Err("Pending request expired".into()));
                false
            } else {
                true
            }
        });
    }

    pub fn size(&self) -> usize {
        self.pending.lock().unwrap().len()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn create_pending_header_format() {
        let manager = InteractionManager::new(InteractionManagerOptions {
            base_url: "https://auth.example".into(),
            interaction_url: "https://auth.example/interact".into(),
            pending_path: None,
            ttl: None,
        });
        let (headers, pending) = manager.create_pending();
        assert!(headers["Location"].contains("/pending/"));
        assert!(headers["AAuth-Requirement"].contains("requirement=interaction"));
        assert!(pending.code.contains('-'));
    }
}
