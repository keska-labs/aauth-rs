use crate::server::access::outcome::AuthTokenFlowOutcome;
use crate::server::deferred::AcceptedResponse;
use crate::types::{AAuthProtocolError, TokenResponseBody};

/// Person Server token exchange / resume result (includes federation-specific outcomes).
#[derive(Debug, Clone, PartialEq)]
pub enum PersonTokenFlowOutcome {
    Flow(AuthTokenFlowOutcome),
    Unauthorized,
    BadGateway,
    Gone,
}

impl PersonTokenFlowOutcome {
    pub fn granted(body: TokenResponseBody) -> Self {
        Self::Flow(AuthTokenFlowOutcome::Granted(body))
    }

    pub fn deferred(accepted: AcceptedResponse) -> Self {
        Self::Flow(AuthTokenFlowOutcome::Deferred(accepted))
    }

    pub fn denied(err: AAuthProtocolError) -> Self {
        Self::Flow(AuthTokenFlowOutcome::Denied(err))
    }
}
