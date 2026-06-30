use crate::server::deferred::{DeferCreated, DeferWaiting, PendingOutcome};
use crate::types::{AAuthProtocolError, TokenResponseBody};

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
