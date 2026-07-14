use crate::deferred::AuthTokenFlowOutcome;
use crate::deferred::DeferCreated;
use crate::protocol::{AAuthProtocolError, PendingBody, TokenResponseBody};

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

    pub fn deferred(defer: DeferCreated) -> Self {
        Self::Flow(AuthTokenFlowOutcome::Deferred(defer))
    }

    pub fn denied(err: AAuthProtocolError) -> Self {
        Self::Flow(AuthTokenFlowOutcome::Denied(err))
    }
}

/// Outcome of starting a PS interaction page visit (`GET ?code=`).
#[derive(Debug, Clone)]
pub enum PersonInteractionOutcome {
    /// Redirect the user to the resource interaction URL (resource-initiated chain).
    Redirect(String),
    /// Interaction code unknown or already consumed.
    InvalidCode,
    /// Pending request TTL expired.
    Expired,
    /// No resource chain — return pending snapshot for integrator consent UI.
    Pending(PendingBody),
}
