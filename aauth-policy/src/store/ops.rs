use aauth::{AuthTokenPollOutcome, poll_outcome_from_snapshot};

use super::traits::{PendingStorable, PendingStore};

/// Load a pending record, expire if needed, and map to a poll outcome.
pub async fn poll_auth_pending<S, R>(
    store: &S,
    pending_id: &str,
) -> Result<AuthTokenPollOutcome, S::Error>
where
    S: PendingStore<R>,
    R: PendingStorable,
{
    let Some(record) = store.load(pending_id).await? else {
        return Ok(AuthTokenPollOutcome::Gone);
    };

    if record.is_expired() {
        let _ = store.remove(pending_id).await;
        return Ok(AuthTokenPollOutcome::Gone);
    }

    Ok(poll_outcome_from_snapshot(record.snapshot()))
}
