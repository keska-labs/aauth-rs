use thiserror::Error;

pub type Result<T> = std::result::Result<T, Error>;

#[derive(Debug, Error)]
pub enum Error {
    #[error("{0}")]
    Message(String),
    #[error("no agent URL provided and none configured")]
    NoAgentUrl,
    #[error("no agent identifier configured for {0}")]
    NoAgentId(String),
    #[error("no signing key found for {0}")]
    NoSigningKey(String),
    #[error("keychain: {0}")]
    Keychain(String),
    #[error("config: {0}")]
    Config(String),
    #[error("jwt: {0}")]
    Jwt(String),
    #[error(transparent)]
    Http(#[from] reqwest::Error),
    #[error(transparent)]
    Json(#[from] serde_json::Error),
    #[error(transparent)]
    Aauth(#[from] aauth::AAuthError),
    #[cfg(feature = "hardware")]
    #[error(transparent)]
    Hardware(#[from] aauth_hardware_keys::Error),
}

impl Error {
    pub fn msg(s: impl Into<String>) -> Self {
        Self::Message(s.into())
    }
}

impl From<Error> for aauth::AAuthError {
    fn from(value: Error) -> Self {
        aauth::AAuthError::Agent(aauth::AgentAuthError::KeyMaterial(value.to_string()))
    }
}
