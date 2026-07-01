use crate::deferred::DeferRequirement;
use crate::protocol::AAuthProtocolError;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AuthGrant {
    pub sub: String,
    pub scope: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TokenPolicyDecision {
    Grant(AuthGrant),
    Deny(AAuthProtocolError),
    Defer(DeferRequirement),
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PersonTokenDecision {
    Grant(AuthGrant),
    Federate,
    Deny(AAuthProtocolError),
    Defer(DeferRequirement),
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ResourceConsentDecision {
    GrantOpaque,
    Deny(AAuthProtocolError),
    Defer(DeferRequirement),
}
