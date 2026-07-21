use crate::protocol::{AAuthProtocolError, TokenResponseBody};

use super::types::DeferRequirement;

const DEFAULT_MAX_POLL_DURATION_SECS: u64 = 300;
const DEFAULT_PREFER_WAIT: u64 = 45;

/// Options for polling an Access Server (or other party) pending URL.
#[derive(Debug, Clone)]
pub struct ServerPollOptions {
    pub location_url: String,
    pub max_poll_duration_secs: Option<u64>,
    pub prefer_wait: Option<u64>,
}

impl ServerPollOptions {
    pub fn new(location_url: impl Into<String>) -> Self {
        Self {
            location_url: location_url.into(),
            max_poll_duration_secs: None,
            prefer_wait: None,
        }
    }
}

/// Terminal or re-defer outcome from polling a pending URL.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ServerPollOutcome {
    AuthToken(TokenResponseBody),
    Deferred {
        requirement: DeferRequirement,
        location_url: String,
    },
    Error(AAuthProtocolError),
    Gone,
}

/// Defaults used by transport adapters when building poll loops.
pub const SERVER_POLL_DEFAULT_MAX_SECS: u64 = DEFAULT_MAX_POLL_DURATION_SECS;
pub const SERVER_POLL_DEFAULT_PREFER_WAIT: u64 = DEFAULT_PREFER_WAIT;
