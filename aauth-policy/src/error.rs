#[derive(Debug, thiserror::Error)]
pub enum PolicyError {
    #[error("{0}")]
    Message(String),
}

/// Person Server policy-service failures that are not store or policy evaluation errors.
#[derive(Debug, thiserror::Error)]
pub enum PersonOrchestrationError {
    #[error("invalid interaction url: {0}")]
    InvalidInteractionUrl(#[source] url::ParseError),
    #[error("interaction url must use https")]
    InteractionUrlNotHttps,
    #[error("resource token missing interaction claim")]
    MissingResourceInteraction,
    #[error("pending body: {0}")]
    PendingBody(#[source] aauth::error::AAuthError),
}
