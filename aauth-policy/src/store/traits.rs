use aauth::{PendingOutcome, PendingSnapshot};

use super::records::PendingRecord;

pub trait PendingStorable: Clone + Send + Sync + 'static {
    fn pending_id(&self) -> &str;
    fn snapshot(&self) -> &PendingSnapshot;
    fn set_snapshot(&mut self, snapshot: PendingSnapshot);
    fn is_expired(&self) -> bool;
}

impl<C> PendingStorable for PendingRecord<C>
where
    C: Clone + Send + Sync + 'static,
{
    fn pending_id(&self) -> &str {
        &self.id
    }

    fn snapshot(&self) -> &PendingSnapshot {
        &self.snapshot
    }

    fn set_snapshot(&mut self, snapshot: PendingSnapshot) {
        self.snapshot = snapshot;
    }

    fn is_expired(&self) -> bool {
        PendingRecord::is_expired(self)
    }
}

#[async_trait::async_trait]
pub trait PendingStore<R: PendingStorable>: Send + Sync + Clone {
    type Error: std::error::Error + Send + Sync + 'static;

    async fn create(&self, record: R) -> Result<String, Self::Error>;
    async fn load(&self, id: &str) -> Result<Option<R>, Self::Error>;
    async fn save(&self, id: &str, record: R) -> Result<(), Self::Error>;
    async fn complete(&self, id: &str, outcome: PendingOutcome) -> Result<(), Self::Error>;
    async fn remove(&self, id: &str) -> Result<(), Self::Error>;

    /// Linear scan for the first record matching `pred`. Default: not supported.
    async fn find_if<F>(&self, pred: F) -> Result<Option<(String, R)>, Self::Error>
    where
        F: Fn(&R) -> bool + Send,
    {
        let _ = pred;
        Ok(None)
    }
}
