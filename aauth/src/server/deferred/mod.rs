mod memory;
#[cfg(feature = "server-axum")]
mod response;
mod util;

pub mod types;

pub use memory::InMemoryPendingStore;
#[cfg(feature = "server-axum")]
pub use response::{build_accepted, build_payment_required_stub, map_snapshot_to_poll_parts, PollResponse};
pub use types::*;
pub use util::{generate_pending_id, pending_location, DEFAULT_PENDING_TTL_SECS};
pub use store::PendingStore;

mod store {
    use super::types::{PendingOutcome, PendingRecord};

    #[async_trait::async_trait]
    pub trait PendingStore: Send + Sync + Clone {
        type Error: std::error::Error + Send + Sync + 'static;

        async fn create(&self, record: PendingRecord) -> Result<String, Self::Error>;
        async fn load(&self, id: &str) -> Result<Option<PendingRecord>, Self::Error>;
        async fn save(&self, id: &str, record: PendingRecord) -> Result<(), Self::Error>;
        async fn complete(&self, id: &str, outcome: PendingOutcome) -> Result<(), Self::Error>;
        async fn remove(&self, id: &str) -> Result<(), Self::Error>;
    }
}
