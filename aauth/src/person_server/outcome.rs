use crate::deferred::{AuthTokenFlowOutcome, DeferCreated};
use crate::protocol::{AAuthProtocolError, PendingBody, TokenResponseBody};

/// Person Server token exchange / resume result (includes federation-specific outcomes).
#[derive(Debug, Clone, PartialEq)]
pub enum PersonTokenFlowOutcome {
    Granted(TokenResponseBody),
    Deferred(DeferCreated),
    Denied(AAuthProtocolError),
    Gone,
    Unauthorized,
    BadGateway,
}

impl PersonTokenFlowOutcome {
    pub fn granted(body: TokenResponseBody) -> Self {
        Self::Granted(body)
    }

    pub fn deferred(defer: DeferCreated) -> Self {
        Self::Deferred(defer)
    }

    pub fn denied(err: AAuthProtocolError) -> Self {
        Self::Denied(err)
    }

    pub fn into_auth_flow(self) -> Option<AuthTokenFlowOutcome> {
        match self {
            Self::Granted(body) => Some(AuthTokenFlowOutcome::Granted(body)),
            Self::Deferred(defer) => Some(AuthTokenFlowOutcome::Deferred(defer)),
            Self::Denied(err) => Some(AuthTokenFlowOutcome::Denied(err)),
            Self::Gone => Some(AuthTokenFlowOutcome::Gone),
            Self::Unauthorized | Self::BadGateway => None,
        }
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
