use aauth::error::AAuthError;

#[derive(Debug, thiserror::Error)]
pub enum PolicyError {
    #[error("{0}")]
    Message(String),
}

impl From<PolicyError> for AAuthError {
    fn from(value: PolicyError) -> Self {
        AAuthError::Message(value.to_string())
    }
}
