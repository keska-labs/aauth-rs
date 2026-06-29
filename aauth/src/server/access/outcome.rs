use crate::server::deferred::{AcceptedResponse, PendingOutcome};
use crate::types::{AAuthProtocolError, TokenResponseBody};

/// Token exchange flow result for Person and Access servers.
#[derive(Debug, Clone, PartialEq)]
pub enum AuthTokenFlowOutcome {
    Granted(TokenResponseBody),
    Deferred(AcceptedResponse),
    Denied(AAuthProtocolError),
    Gone,
}

impl AuthTokenFlowOutcome {
    pub fn granted(body: TokenResponseBody) -> Self {
        Self::Granted(body)
    }

    pub fn deferred(accepted: AcceptedResponse) -> Self {
        Self::Deferred(accepted)
    }

    pub fn denied(err: AAuthProtocolError) -> Self {
        Self::Denied(err)
    }
}

/// Pending poll result for Person and Access servers.
#[derive(Debug, Clone, PartialEq)]
pub enum AuthTokenPollOutcome {
    Pending(AcceptedResponse),
    Complete(PendingOutcome),
    Gone,
}
