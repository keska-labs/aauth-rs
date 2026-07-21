use thiserror::Error;

pub type Result<T> = std::result::Result<T, Error>;

#[derive(Debug, Error)]
#[non_exhaustive]
pub enum Error {
    #[error("missing Signature-Key header")]
    MissingSignatureKey,

    #[error("missing Signature-Input header")]
    MissingSignatureInput,

    #[error("missing Signature header")]
    MissingSignature,

    #[error("Signature-Key missing jwt parameter")]
    MissingJwtParam,

    #[error("Signature-Input missing required component: {0}")]
    MissingComponent(&'static str),

    #[error("authorization covered but Authorization header missing")]
    AuthorizationHeaderMissing,

    #[error("signature created in the future")]
    CreatedInFuture,

    #[error("signature expired")]
    Expired,

    #[error("Signature-Input missing created")]
    MissingCreated,

    #[error("invalid Signature-Input created")]
    InvalidCreated(#[source] std::num::ParseIntError),

    #[error("invalid Signature header format")]
    InvalidSignatureFormat,

    #[error("invalid encoding")]
    InvalidEncoding(#[source] base64::DecodeError),

    #[error("invalid key length")]
    InvalidKeyLength,

    #[error("unsupported signing JWK: kty={kty} crv={crv}")]
    UnsupportedSigningJwk { kty: String, crv: String },

    #[error("EC JWK missing y coordinate")]
    MissingEcY,

    #[error("HTTP signature verification failed")]
    VerificationFailed,

    #[error("unsupported Signature-Key scheme: {0}")]
    UnsupportedScheme(String),

    #[error("hwk scheme is not supported for signing with this API")]
    HwkSignUnsupported,

    #[error("invalid header value")]
    InvalidHeaderValue(#[source] http::header::InvalidHeaderValue),

    #[error("Signature-Input missing covered components")]
    MissingCoveredComponents,

    #[error("invalid Signature-Key header")]
    InvalidSignatureKey(String),

    #[error("invalid JWT in Signature-Key")]
    InvalidJwt(String),

    #[error("JWT missing cnf.jwk")]
    MissingCnfJwk,

    #[error("httpsig error: {0}")]
    Httpsig(String),

    #[error("JSON error")]
    Json(#[from] serde_json::Error),

    #[error("SFV parse error: {0}")]
    Sfv(String),
}

impl From<httpsig::prelude::HttpSigError> for Error {
    fn from(value: httpsig::prelude::HttpSigError) -> Self {
        Self::Httpsig(value.to_string())
    }
}
