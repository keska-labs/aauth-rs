use thiserror::Error;

#[derive(Debug, Error)]
pub enum AAuthError {
    #[error("{0}")]
    Message(String),

    #[error("invalid header: {0}")]
    InvalidHeader(String),

    #[error("http error: {0}")]
    Http(#[from] HttpError),

    #[error("jwt error: {0}")]
    Jwt(#[from] JwtError),

    #[error("token error: {code}: {message}")]
    Token { code: String, message: String },
}

impl AAuthError {
    pub fn message(message: impl Into<String>) -> Self {
        Self::Message(message.into())
    }
}

#[derive(Debug, Error)]
pub enum HttpError {
    #[error("request failed: {0}")]
    Request(String),

    #[error("status {status}: {body}")]
    Status { status: u16, body: String },
}

#[derive(Debug, Error)]
pub enum JwtError {
    #[error("decode failed: {0}")]
    Decode(String),

    #[error("invalid typ: {0}")]
    InvalidTyp(String),

    #[error("missing claim: {0}")]
    MissingClaim(String),
}

/// Token verification errors aligned with the TypeScript reference.
#[derive(Debug, Error, Clone, PartialEq, Eq)]
#[error("{code}: {message}")]
pub struct TokenError {
    pub code: String,
    pub message: String,
}

impl TokenError {
    pub fn new(code: impl Into<String>, message: impl Into<String>) -> Self {
        Self {
            code: code.into(),
            message: message.into(),
        }
    }
}

impl From<TokenError> for AAuthError {
    fn from(value: TokenError) -> Self {
        Self::Token {
            code: value.code,
            message: value.message,
        }
    }
}

pub type Result<T> = std::result::Result<T, AAuthError>;
