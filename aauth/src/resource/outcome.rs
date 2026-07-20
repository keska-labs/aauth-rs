use crate::deferred::AuthTokenPollOutcome;
use crate::deferred::DeferCreated;
use crate::deferred::poll_outcome_from_snapshot;
use crate::deferred::types::PendingSnapshot;
use crate::protocol::AAuthProtocolError;

/// Resource-managed consent evaluation result.
#[derive(Debug, Clone, PartialEq)]
pub enum ResourceConsentFlowOutcome {
    GrantOpaque(String),
    Deferred(DeferCreated),
    Denied(AAuthProtocolError),
}

/// Resource pending poll result (same wire shape as auth token poll).
pub type ResourcePollOutcome = AuthTokenPollOutcome;

/// Resource poll mapping (same wire shape; removes completed record in handler if needed).
pub fn resource_poll_outcome_from_snapshot(snapshot: &PendingSnapshot) -> ResourcePollOutcome {
    poll_outcome_from_snapshot(snapshot)
}
