mod memory;
mod outcome;
#[cfg(feature = "deferred-http")]
mod parse;
#[cfg(feature = "deferred-http")]
mod poll;
mod util;

pub mod types;

pub use memory::{
    InMemoryAccessPendingStore, InMemoryPendingStore, InMemoryPersonPendingStore,
    InMemoryResourcePendingStore,
};
pub use outcome::{AuthTokenFlowOutcome, AuthTokenPollOutcome};
#[cfg(feature = "deferred-http")]
pub use parse::{
    ParsedDeferred, parse_auth_token_response, parse_deferred_response, resolve_deferred_location,
};
#[cfg(feature = "deferred-http")]
pub use poll::{
    OutboundSignatureProvider, ServerPollOptions, ServerPollOutcome, poll_pending_http,
    post_pending_input,
};
pub use store::{PendingStorable, PendingStore};
pub use types::*;
pub use util::{DEFAULT_PENDING_TTL_SECS, generate_pending_id, pending_location};

mod store {
    use super::types::{PendingOutcome, PendingRecord, PendingSnapshot};

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
}
