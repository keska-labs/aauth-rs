use crate::server::access::outcome::AuthTokenPollOutcome;
use crate::server::deferred::AcceptedResponse;
use crate::types::AAuthProtocolError;

/// Resource-managed consent evaluation result.
#[derive(Debug, Clone, PartialEq)]
pub enum ResourceConsentFlowOutcome {
    GrantOpaque(String),
    Deferred(AcceptedResponse),
    Denied(AAuthProtocolError),
}

/// Resource pending poll result (same wire shape as auth token poll).
pub type ResourcePollOutcome = AuthTokenPollOutcome;
