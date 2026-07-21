use thiserror::Error;

use crate::protocol::{AAuthErrorCode, AAuthProtocolError, JwtTyp};

/// Library-wide error umbrella. Domain failures nest with `#[source]`; wire JSON uses
/// [`AAuthProtocolError`] / [`IntoAauthProtocol`] at HTTP edges.
#[derive(Debug, Error)]
#[non_exhaustive]
pub enum AAuthError {
    #[error(transparent)]
    Jwt(#[from] JwtError),

    #[error(transparent)]
    Signature(#[from] SignatureError),

    #[error(transparent)]
    Metadata(#[from] MetadataError),

    #[error(transparent)]
    Verify(#[from] VerifyError),

    #[error(transparent)]
    Deferred(#[from] DeferredError),

    #[error(transparent)]
    Header(#[from] HeaderError),

    #[error(transparent)]
    Agent(#[from] AgentAuthError),

    #[error(transparent)]
    ResourceToken(#[from] ResourceTokenError),
}

/// Map a domain error to an optional HTTP status + protocol JSON body.
pub trait IntoAauthProtocol {
    fn into_aauth_protocol(self) -> Option<(u16, AAuthProtocolError)>;
}

#[derive(Debug, Error)]
#[non_exhaustive]
pub enum JwtError {
    #[error("JWT decode failed: {0}")]
    Decode(#[source] jsonwebtoken::errors::Error),

    #[error("missing typ header")]
    MissingTyp,

    #[error("unknown typ: {0}")]
    UnknownTyp(String),

    #[error("JWT alg none is not accepted")]
    AlgNone,

    #[error("unsupported JWK kty: {0}")]
    UnsupportedKty(String),

    #[error("JWK thumbprint failed: {0}")]
    Thumbprint(String),

    #[error("JWK canonicalize failed")]
    Canonicalize(#[source] serde_json::Error),

    #[error("JWK set decode failed")]
    JwkSet(#[source] serde_json::Error),
}

#[derive(Debug, Error)]
#[non_exhaustive]
pub enum SignatureError {
    #[error("missing signature-key header")]
    MissingSignatureKey,

    #[error("signature-key missing jwt parameter")]
    MissingJwtParam,

    #[error("signature-key jwt not quoted")]
    JwtNotQuoted,

    #[error("missing signature-input header")]
    MissingSignatureInput,

    #[error("missing signature header")]
    MissingSignature,

    #[error("signature-input missing required component: {0}")]
    MissingComponent(&'static str),

    #[error("signature-input missing authorization component")]
    MissingAuthorizationComponent,

    #[error("authorization covered but Authorization header missing")]
    AuthorizationHeaderMissing,

    #[error("signature created in the future")]
    CreatedInFuture,

    #[error("signature expired")]
    Expired,

    #[error("signature-input missing created")]
    MissingCreated,

    #[error("invalid signature-input created")]
    InvalidCreated(#[source] std::num::ParseIntError),

    #[error("invalid signature header format")]
    InvalidSignatureFormat,

    #[error("invalid signature encoding")]
    InvalidEncoding(#[source] base64::DecodeError),

    #[error("invalid key length")]
    InvalidKeyLength,

    #[error("unsupported signing JWK: kty={kty} crv={crv}")]
    UnsupportedSigningJwk { kty: String, crv: String },

    #[error("EC signing JWK missing y coordinate")]
    MissingEcY,

    #[error("HTTP signature verification failed")]
    VerificationFailed,

    #[error("hwk signature key not supported")]
    HwkUnsupported,

    #[error("invalid header value")]
    InvalidHeaderValue(#[source] http::header::InvalidHeaderValue),

    #[error("signature-input missing covered components")]
    MissingCoveredComponents,

    #[error("httpsig-key error: {0}")]
    HttpsigKey(String),

    #[error(transparent)]
    Jwt(#[from] JwtError),
}

impl SignatureError {
    /// Whether this failure means no AAuth agent token was presented.
    ///
    /// Spec: `draft-hardt-oauth-aauth-protocol.md#requirement-agent-token`
    pub fn is_missing_agent_credential(&self) -> bool {
        matches!(
            self,
            Self::MissingSignatureKey
                | Self::MissingJwtParam
                | Self::MissingSignature
                | Self::MissingSignatureInput
                | Self::HwkUnsupported
        )
    }

    /// Signature-Key draft error code for the `Signature-Error` header.
    ///
    /// Spec: `draft-hardt-httpbis-signature-key-05.txt` §5.4
    pub fn signature_error_code(&self) -> &'static str {
        match self {
            Self::MissingComponent(_)
            | Self::MissingAuthorizationComponent
            | Self::AuthorizationHeaderMissing
            | Self::MissingCoveredComponents => "invalid_input",
            Self::MissingJwtParam | Self::JwtNotQuoted | Self::Jwt(_) => "invalid_jwt",
            Self::UnsupportedSigningJwk { .. } => "unsupported_algorithm",
            Self::InvalidKeyLength | Self::MissingEcY | Self::HwkUnsupported => "invalid_key",
            Self::MissingSignatureKey
            | Self::MissingSignatureInput
            | Self::MissingSignature
            | Self::CreatedInFuture
            | Self::Expired
            | Self::MissingCreated
            | Self::InvalidCreated(_)
            | Self::InvalidSignatureFormat
            | Self::InvalidEncoding(_)
            | Self::VerificationFailed
            | Self::InvalidHeaderValue(_)
            | Self::HttpsigKey(_) => "invalid_signature",
        }
    }
}

#[derive(Debug, Error)]
#[non_exhaustive]
pub enum MetadataError {
    #[error("HTTP {status} fetching {url}")]
    HttpStatus { url: String, status: u16 },

    #[error("request failed for {url}")]
    Request {
        url: String,
        #[source]
        source: Box<dyn std::error::Error + Send + Sync>,
    },

    #[error("invalid metadata/JWKS JSON from {url}")]
    Decode {
        url: String,
        #[source]
        source: serde_json::Error,
    },

    #[error("missing jwks_uri in metadata from {url}")]
    MissingJwksUri { url: String },

    #[error("missing token_endpoint in metadata")]
    MissingTokenEndpoint,

    #[error("JWKS fetch rate limited for {jwks_uri}")]
    RateLimited { jwks_uri: String },

    #[error("unknown JWKS URI: {0}")]
    UnknownJwksUri(String),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum VerifyReason {
    WrongTyp,
    InvalidDwk,
    SignatureFailed,
    ExpectedAuth,
    UnsupportedTyp,
    FutureIat,
    InvalidIss,
    InvalidPs,
    InvalidParentAgent,
}

#[derive(Debug, Error)]
#[non_exhaustive]
pub enum VerifyError {
    #[error("token expired")]
    Expired { typ: JwtTyp },

    #[error("invalid token ({typ:?})")]
    Invalid { typ: JwtTyp, reason: VerifyReason },

    #[error("cnf.jwk thumbprint does not match HTTP signature key")]
    KeyBindingFailed,

    #[error("auth token aud mismatch")]
    AudMismatch,

    #[error("resource token iss mismatch")]
    IssMismatch,

    #[error("agent mismatch")]
    AgentMismatch,

    #[error("agent_jkt mismatch")]
    AgentJktMismatch,

    #[error("missing kid")]
    MissingKid,

    #[error("unknown kid: {0}")]
    UnknownKid(String),

    #[error("{code}: {message}")]
    Token { code: String, message: String },

    #[error(transparent)]
    Metadata(#[from] MetadataError),

    #[error(transparent)]
    Jwt(#[from] JwtError),

    #[error("cannot determine resource token audience")]
    NoAudience,
}

impl VerifyError {
    pub fn token(code: impl Into<String>, message: impl Into<String>) -> Self {
        Self::Token {
            code: code.into(),
            message: message.into(),
        }
    }

    /// Signature-Key draft error code for the `Signature-Error` header.
    ///
    /// Spec: `draft-hardt-httpbis-signature-key-05.txt` §5.4;
    /// AAuth `#verification` step 5
    pub fn signature_error_code(&self) -> &'static str {
        match self {
            Self::Expired { .. } => "expired_jwt",
            Self::KeyBindingFailed => "invalid_key",
            Self::MissingKid | Self::UnknownKid(_) => "unknown_key",
            Self::Token { code, .. } if code.contains("expired") => "expired_jwt",
            Self::Invalid { .. }
            | Self::AudMismatch
            | Self::IssMismatch
            | Self::AgentMismatch
            | Self::AgentJktMismatch
            | Self::Token { .. }
            | Self::Metadata(_)
            | Self::Jwt(_)
            | Self::NoAudience => "invalid_jwt",
        }
    }
}

#[derive(Debug, Error)]
#[non_exhaustive]
pub enum DeferredError {
    #[error("expected status {expected}, got {got}")]
    UnexpectedStatus { expected: u16, got: u16 },

    #[error("202 missing Location")]
    MissingLocation,

    #[error("202 missing AAuth-Requirement")]
    MissingRequirement,

    #[error(transparent)]
    Requirement(#[from] HeaderError),

    #[error("invalid pending JSON body")]
    Body(#[source] serde_json::Error),

    #[error("polling timed out after {0}s")]
    TimedOut(u64),

    #[error("pending POST failed with status {0}")]
    PostFailed(u16),

    #[error("pending poll returned 200 without auth token")]
    MissingAuthTokenBody,

    #[error("payment defer is not a pending JSON body")]
    PaymentNotPendingBody,

    #[error("payment defer uses 402, not AAuth-Requirement")]
    PaymentNotRequirement,

    #[error("invalid pending URL")]
    InvalidUrl(#[source] url::ParseError),

    #[error("pending URL missing host")]
    MissingHost,

    #[cfg(feature = "deferred-http")]
    #[error("HTTP request failed")]
    Transport(#[source] reqwest::Error),

    #[cfg(feature = "deferred-http")]
    #[error("invalid response body")]
    ResponseBody(#[source] reqwest::Error),

    #[error("failed to serialize request body")]
    Serialize(#[source] serde_json::Error),
}

#[derive(Debug, Error)]
#[non_exhaustive]
pub enum HeaderError {
    #[error("empty AAuth-Requirement header")]
    EmptyRequirement,

    #[error("missing requirement= in AAuth-Requirement")]
    MissingRequirementMember,

    #[error("unknown requirement level: {0}")]
    UnknownRequirement(String),

    #[error("auth-token requires resource-token")]
    MissingResourceToken,

    #[error("interaction requires url")]
    MissingInteractionUrl,

    #[error("interaction requires code")]
    MissingInteractionCode,

    #[error("mission missing approver")]
    MissingApprover,

    #[error("mission missing s256")]
    MissingS256,

    #[error("invalid header: {0}")]
    Invalid(String),
}

#[derive(Debug, Error)]
#[non_exhaustive]
pub enum AgentAuthError {
    #[error("invalid resource URL")]
    InvalidOrigin(#[source] url::ParseError),

    #[error("person server unresolved: no config and no agent ps claim")]
    PersonServerUnresolved,

    #[error("expected agent JWT for person server resolution")]
    ExpectedAgentJwt,

    #[error("hwk signature key cannot supply agent JWT")]
    HwkUnsupported,
}

#[derive(Debug, Error)]
#[non_exhaustive]
pub enum ResourceTokenError {
    #[error("clock error")]
    SystemTime(#[source] std::time::SystemTimeError),

    #[error("JWT encode failed")]
    Encode(#[source] jsonwebtoken::errors::Error),
}

impl IntoAauthProtocol for SignatureError {
    fn into_aauth_protocol(self) -> Option<(u16, AAuthProtocolError)> {
        Some((
            401,
            AAuthProtocolError::with_description(
                AAuthErrorCode::InvalidSignature,
                self.to_string(),
            ),
        ))
    }
}

impl IntoAauthProtocol for VerifyError {
    fn into_aauth_protocol(self) -> Option<(u16, AAuthProtocolError)> {
        let (status, code, desc) = match &self {
            Self::Expired { typ } => {
                let code = match typ {
                    JwtTyp::Agent => AAuthErrorCode::ExpiredAgentToken,
                    JwtTyp::Resource => AAuthErrorCode::ExpiredResourceToken,
                    JwtTyp::Auth => AAuthErrorCode::ExpiredJwt,
                };
                (401, code, self.to_string())
            }
            Self::Invalid {
                typ: JwtTyp::Agent, ..
            } => (401, AAuthErrorCode::InvalidAgentToken, self.to_string()),
            Self::Invalid {
                typ: JwtTyp::Resource,
                ..
            } => (401, AAuthErrorCode::InvalidResourceToken, self.to_string()),
            Self::Invalid {
                typ: JwtTyp::Auth, ..
            } => (401, AAuthErrorCode::InvalidJwt, self.to_string()),
            Self::KeyBindingFailed => (401, AAuthErrorCode::InvalidKey, self.to_string()),
            Self::MissingKid | Self::UnknownKid(_) => {
                (401, AAuthErrorCode::UnknownKey, self.to_string())
            }
            Self::Token { code, message } => {
                let mapped = match code.as_str() {
                    "invalid_agent_token" => AAuthErrorCode::InvalidAgentToken,
                    "expired_agent_token" => AAuthErrorCode::ExpiredAgentToken,
                    "invalid_resource_token" => AAuthErrorCode::InvalidResourceToken,
                    "expired_resource_token" => AAuthErrorCode::ExpiredResourceToken,
                    "invalid_jwt" => AAuthErrorCode::InvalidJwt,
                    other => AAuthErrorCode::Custom(other.to_string()),
                };
                return Some((
                    401,
                    AAuthProtocolError::with_description(mapped, message.clone()),
                ));
            }
            _ => (401, AAuthErrorCode::InvalidJwt, self.to_string()),
        };
        Some((status, AAuthProtocolError::with_description(code, desc)))
    }
}

impl IntoAauthProtocol for AAuthError {
    fn into_aauth_protocol(self) -> Option<(u16, AAuthProtocolError)> {
        match self {
            Self::Signature(e) => e.into_aauth_protocol(),
            Self::Verify(e) => e.into_aauth_protocol(),
            Self::Jwt(e) => Some((
                401,
                AAuthProtocolError::with_description(AAuthErrorCode::InvalidJwt, e.to_string()),
            )),
            Self::Header(e) => Some((
                400,
                AAuthProtocolError::with_description(AAuthErrorCode::InvalidRequest, e.to_string()),
            )),
            _ => None,
        }
    }
}

impl AAuthError {
    /// Whether this failure means no AAuth agent token was presented.
    pub fn is_missing_agent_credential(&self) -> bool {
        match self {
            Self::Signature(e) => e.is_missing_agent_credential(),
            _ => false,
        }
    }

    /// Build a `Signature-Error` header for signature / JWT verification failures.
    ///
    /// Spec: `draft-hardt-oauth-aauth-protocol.md#verification`
    pub fn signature_error_header(&self) -> Option<httpsig_key::SignatureErrorHeader> {
        let code = match self {
            Self::Signature(e) => e.signature_error_code(),
            Self::Verify(e) => e.signature_error_code(),
            Self::Jwt(JwtError::AlgNone) => "invalid_jwt",
            Self::Jwt(_) => "invalid_jwt",
            _ => return None,
        };
        Some(httpsig_key::SignatureErrorHeader::new(code))
    }
}

pub type Result<T> = std::result::Result<T, AAuthError>;
