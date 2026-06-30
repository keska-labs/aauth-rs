use std::collections::HashMap;
use std::sync::{Arc, Mutex};

use super::store::{PendingStorable, PendingStore};
use super::types::{
    AccessPendingRecord, PendingOutcome, PendingSnapshot, PersonPendingRecord,
    ResourcePendingRecord,
};

#[derive(Debug, Clone)]
pub struct InMemoryPendingStore<R> {
    inner: Arc<Mutex<HashMap<String, R>>>,
    pub last_created: Arc<Mutex<Option<String>>>,
}

pub type InMemoryPersonPendingStore = InMemoryPendingStore<PersonPendingRecord>;
pub type InMemoryAccessPendingStore = InMemoryPendingStore<AccessPendingRecord>;
pub type InMemoryResourcePendingStore = InMemoryPendingStore<ResourcePendingRecord>;

impl<R> Default for InMemoryPendingStore<R>
where
    R: PendingStorable,
{
    fn default() -> Self {
        Self::new()
    }
}

impl<R> InMemoryPendingStore<R>
where
    R: PendingStorable,
{
    pub fn new() -> Self {
        Self {
            inner: Arc::new(Mutex::new(HashMap::new())),
            last_created: Arc::new(Mutex::new(None)),
        }
    }

    pub fn len(&self) -> usize {
        self.inner.lock().unwrap().len()
    }

    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    pub fn last_id(&self) -> Option<String> {
        self.inner.lock().unwrap().keys().next().cloned()
    }
}

#[async_trait::async_trait]
impl<R> PendingStore<R> for InMemoryPendingStore<R>
where
    R: PendingStorable,
{
    type Error = std::io::Error;

    async fn create(&self, record: R) -> Result<String, Self::Error> {
        let id = record.pending_id().to_string();
        *self.last_created.lock().unwrap() = Some(id.clone());
        self.inner.lock().unwrap().insert(id.clone(), record);
        Ok(id)
    }

    async fn load(&self, id: &str) -> Result<Option<R>, Self::Error> {
        Ok(self.inner.lock().unwrap().get(id).cloned())
    }

    async fn save(&self, id: &str, record: R) -> Result<(), Self::Error> {
        self.inner.lock().unwrap().insert(id.to_string(), record);
        Ok(())
    }

    async fn complete(&self, id: &str, outcome: PendingOutcome) -> Result<(), Self::Error> {
        let mut guard = self.inner.lock().unwrap();
        if let Some(record) = guard.get_mut(id) {
            record.set_snapshot(PendingSnapshot::complete(outcome));
        }
        Ok(())
    }

    async fn remove(&self, id: &str) -> Result<(), Self::Error> {
        self.inner.lock().unwrap().remove(id);
        Ok(())
    }
}
