use std::collections::HashMap;
use std::sync::{Arc, Mutex};

use super::types::{PendingOutcome, PendingRecord, PendingSnapshot};
use super::PendingStore;

#[derive(Debug, Clone)]
pub struct InMemoryPendingStore {
    inner: Arc<Mutex<HashMap<String, PendingRecord>>>,
    pub last_created: Arc<Mutex<Option<String>>>,
}

impl Default for InMemoryPendingStore {
    fn default() -> Self {
        Self::new()
    }
}

impl InMemoryPendingStore {
    pub fn new() -> Self {
        Self {
            inner: Arc::new(Mutex::new(HashMap::new())),
            last_created: Arc::new(Mutex::new(None)),
        }
    }

    pub fn len(&self) -> usize {
        self.inner.lock().unwrap().len()
    }

    pub fn last_id(&self) -> Option<String> {
        self.inner
            .lock()
            .unwrap()
            .keys()
            .next()
            .cloned()
    }
}

#[async_trait::async_trait]
impl PendingStore for InMemoryPendingStore {
    type Error = std::io::Error;

    async fn create(&self, record: PendingRecord) -> Result<String, Self::Error> {
        let id = record.id.clone();
        *self.last_created.lock().unwrap() = Some(id.clone());
        self.inner.lock().unwrap().insert(id.clone(), record);
        Ok(id)
    }

    async fn load(&self, id: &str) -> Result<Option<PendingRecord>, Self::Error> {
        Ok(self.inner.lock().unwrap().get(id).cloned())
    }

    async fn save(&self, id: &str, record: PendingRecord) -> Result<(), Self::Error> {
        self.inner.lock().unwrap().insert(id.to_string(), record);
        Ok(())
    }

    async fn complete(&self, id: &str, outcome: PendingOutcome) -> Result<(), Self::Error> {
        let mut guard = self.inner.lock().unwrap();
        if let Some(record) = guard.get_mut(id) {
            record.snapshot = PendingSnapshot::complete(outcome);
        }
        Ok(())
    }

    async fn remove(&self, id: &str) -> Result<(), Self::Error> {
        self.inner.lock().unwrap().remove(id);
        Ok(())
    }
}
