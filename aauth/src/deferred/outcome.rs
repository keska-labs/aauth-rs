use crate::protocol::{AAuthProtocolError, TokenResponseBody};

use super::types::PendingSnapshot;
use super::{DeferCreated, DeferWaiting, PendingOutcome};

/// Token exchange flow result for Person and Access servers.
#[derive(Debug, Clone, PartialEq)]
pub enum AuthTokenFlowOutcome {
    Granted(TokenResponseBody),
    Deferred(DeferCreated),
    Denied(AAuthProtocolError),
    Gone,
}

impl AuthTokenFlowOutcome {
    pub fn granted(body: TokenResponseBody) -> Self {
        Self::Granted(body)
    }

    pub fn deferred(defer: DeferCreated) -> Self {
        Self::Deferred(defer)
    }

    pub fn denied(err: AAuthProtocolError) -> Self {
        Self::Denied(err)
    }
}

/// Pending poll result for Person and Access servers.
#[derive(Debug, Clone, PartialEq)]
pub enum AuthTokenPollOutcome {
    Pending(DeferWaiting),
    Complete(PendingOutcome),
    Gone,
}

/// Map a pending snapshot to a poll outcome (for service poll methods).
pub fn poll_outcome_from_snapshot(snapshot: &PendingSnapshot) -> AuthTokenPollOutcome {
    match snapshot {
        PendingSnapshot::Complete(outcome) => AuthTokenPollOutcome::Complete(outcome.clone()),
        PendingSnapshot::Waiting {
            status,
            requirement,
        } => AuthTokenPollOutcome::Pending(DeferWaiting {
            status: *status,
            requirement: requirement.clone(),
        }),
    }
}
