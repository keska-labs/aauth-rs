use serde::{Deserialize, Serialize};

use crate::error::{AAuthError, Result, TokenError};
use crate::types::{JwtTyp, Mission};

use super::decode::{decode_unverified, decode_verified, verified_validation};

/// Ed25519 OKP public JWK (`kty`, `crv`, `x`).
///
/// Spec: https://github.com/dickhardt/AAuth/blob/main/draft-hardt-oauth-aauth-protocol.md#jwks-discovery-and-caching-jwks-discovery
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct OkpJwk {
    /// Key type. OKP keys use `"OKP"`.
    pub kty: String,
    /// Curve name. Ed25519 keys use `"Ed25519"`.
    pub crv: String,
    /// Base64url-encoded public key coordinate.
    pub x: String,
    /// Key identifier, matched against the JWT header `kid` during verification.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub kid: Option<String>,
}

/// Ed25519 OKP private JWK used locally for HTTP request signing.
///
/// Spec: https://github.com/dickhardt/AAuth/blob/main/draft-hardt-oauth-aauth-protocol.md#keying-material
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct OkpSigningJwk {
    /// Key type. OKP keys use `"OKP"`.
    pub kty: String,
    /// Curve name. Ed25519 keys use `"Ed25519"`.
    pub crv: String,
    /// Base64url-encoded public key coordinate.
    pub x: String,
    /// Base64url-encoded private key coordinate.
    pub d: String,
    /// Key identifier published in JWKS and referenced by JWT header `kid`.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub kid: Option<String>,
}

impl OkpSigningJwk {
    pub fn public_jwk(&self) -> OkpJwk {
        OkpJwk {
            kty: self.kty.clone(),
            crv: self.crv.clone(),
            x: self.x.clone(),
            kid: self.kid.clone(),
        }
    }
}

/// RFC 7800 confirmation claim binding a token to a public key.
///
/// Spec: https://github.com/dickhardt/AAuth/blob/main/draft-hardt-oauth-aauth-protocol.md#agent-token-structure
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CnfClaim {
    /// Agent public key. MUST match the key used to sign the HTTP request.
    pub jwk: OkpJwk,
}

/// RFC 8693-style delegation chain node in an auth token.
///
/// Spec: https://github.com/dickhardt/AAuth/blob/main/draft-hardt-oauth-aauth-protocol.md#delegation-chain
///
/// When the upstream agent was itself delegated to, its upstream is recorded as a nested
/// [`act`](Self::act) claim.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ActClaim {
    /// `aauth:` URI of the immediate upstream agent.
    pub agent: String,
    /// Nested upstream delegation, when present.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub act: Option<Box<ActClaim>>,
}

/// Agent token JWT payload (`typ: aa-agent+jwt`).
///
/// Spec: https://github.com/dickhardt/AAuth/blob/main/draft-hardt-oauth-aauth-protocol.md#agent-token-agent-tokens
///
/// Agent tokens SHOULD NOT have a lifetime exceeding 24 hours.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AgentClaims {
    /// Agent provider URL.
    pub iss: String,
    /// Well-known metadata document name for key discovery. MUST be `aauth-agent.json`.
    pub dwk: String,
    /// Agent identifier (`aauth:local@domain`), stable across key rotations.
    pub sub: String,
    /// Unique token identifier for replay detection, audit, and revocation.
    pub jti: String,
    /// Confirmation claim with the agent's public key.
    pub cnf: CnfClaim,
    /// Issued-at timestamp.
    pub iat: i64,
    /// Expiration timestamp.
    pub exp: i64,
    /// HTTPS URL of the agent's person server. Distinct from `iss`.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub ps: Option<String>,
    /// Parent agent identifier when this token belongs to a sub-agent.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub parent_agent: Option<String>,
}

impl AgentClaims {
    pub fn identifier(&self) -> &str {
        &self.sub
    }
}

/// Auth token JWT payload (`typ: aa-auth+jwt`).
///
/// Spec: https://github.com/dickhardt/AAuth/blob/main/draft-hardt-oauth-aauth-protocol.md#auth-token-auth-tokens
///
/// At least one of [`sub`](Self::sub) or [`scope`](Self::scope) MUST be present.
/// Auth tokens MUST NOT have a lifetime exceeding 1 hour.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AuthClaims {
    /// URL of the server that issued the auth token (AS or PS).
    pub iss: String,
    /// Well-known metadata document name for key discovery. `aauth-access.json` when issued by an AS,
    /// `aauth-person.json` when issued by a PS.
    pub dwk: String,
    /// URL of the resource the agent is authorized to access.
    pub aud: String,
    /// Unique token identifier for replay detection, audit, and revocation.
    pub jti: String,
    /// Agent identifier authorized to use this token.
    pub agent: String,
    /// Upstream delegation chain. Absent when the agent obtained the token directly.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub act: Option<ActClaim>,
    /// Confirmation claim with the agent's public key. MUST match the request signing key.
    pub cnf: CnfClaim,
    /// Issued-at timestamp.
    pub iat: i64,
    /// Expiration timestamp.
    pub exp: i64,
    /// Directed user identifier. PS SHOULD provide a pairwise pseudonymous identifier per `aud`.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub sub: Option<String>,
    /// Authorized scopes as a space-separated string. MUST NOT be broader than the resource token scope.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub scope: Option<String>,
    /// Tenant identifier per OpenID Connect Enterprise Extensions. When present, `(iss, tenant, sub)`
    /// identifies a user within an organization.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub tenant: Option<String>,
    /// Mission reference when the auth token was issued in mission context.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub mission: Option<Mission>,
}

impl AuthClaims {
    pub fn validate(&self) -> Result<()> {
        if self.sub.is_none() && self.scope.is_none() {
            return Err(AAuthError::from(TokenError::new(
                JwtTyp::Auth.verify_error_code(),
                "at least one of sub or scope must be present",
            )));
        }
        Ok(())
    }
}

/// Resource-initiated interaction embedded in a resource token.
///
/// Spec: https://github.com/dickhardt/AAuth/blob/main/draft-hardt-oauth-aauth-protocol.md#resource-token-structure
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ResourceInteractionClaim {
    /// HTTPS URL of the resource's interaction endpoint.
    pub url: String,
    /// Interaction code to present at that URL.
    pub code: String,
}

/// Resource token JWT payload (`typ: aa-resource+jwt`).
///
/// Spec: https://github.com/dickhardt/AAuth/blob/main/draft-hardt-oauth-aauth-protocol.md#resource-token-structure
///
/// Resource tokens SHOULD NOT have a lifetime exceeding 5 minutes.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ResourceClaims {
    /// Resource URL.
    pub iss: String,
    /// Well-known metadata document name for key discovery. MUST be `aauth-resource.json`.
    pub dwk: String,
    /// Token audience: PS URL (three-party) or AS URL (four-party).
    pub aud: String,
    /// Unique token identifier for replay detection, audit, and revocation.
    pub jti: String,
    /// Agent identifier the token is issued for.
    pub agent: String,
    /// JWK Thumbprint of the agent's current signing key.
    pub agent_jkt: String,
    /// Issued-at timestamp.
    pub iat: u64,
    /// Expiration timestamp.
    pub exp: u64,
    /// Requested scopes as a space-separated string.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub scope: Option<String>,
    /// Mission reference when the resource is mission-aware and the agent sent `AAuth-Mission`.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub mission: Option<Mission>,
    /// Present when the resource requires its own user-facing flow before authorization can proceed.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub interaction: Option<ResourceInteractionClaim>,
}

/// Verified AAuth JWT, tagged by header `typ`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum VerifiedToken {
    Agent(AgentClaims),
    Auth(AuthClaims),
}

impl VerifiedToken {
    pub fn decode_unverified(jwt: &str) -> Result<Self> {
        let typ = JwtTyp::from_jwt(jwt)?;
        let error_code = typ.verify_error_code();

        match typ {
            JwtTyp::Agent => decode_unverified::<AgentClaims>(jwt)
                .map(|data| Self::Agent(data.claims))
                .map_err(|e| decode_err(error_code, e)),
            JwtTyp::Auth => {
                let claims = decode_unverified::<AuthClaims>(jwt)
                    .map_err(|e| decode_err(error_code, e))?
                    .claims;
                claims.validate()?;
                Ok(Self::Auth(claims))
            }
            JwtTyp::Resource => Err(AAuthError::from(TokenError::new(
                typ.verify_error_code(),
                format!("Unsupported JWT typ for verification: {typ}"),
            ))),
        }
    }

    pub fn decode_verified(jwt: &str, key: &jsonwebtoken::DecodingKey) -> Result<Self> {
        let typ = JwtTyp::from_jwt(jwt)?;
        let error_code = typ.verify_error_code();
        let validation = verified_validation();

        match typ {
            JwtTyp::Agent => decode_verified::<AgentClaims>(jwt, key, &validation)
                .map(|data| Self::Agent(data.claims))
                .map_err(|e| decode_err(error_code, e)),
            JwtTyp::Auth => {
                let claims = decode_verified::<AuthClaims>(jwt, key, &validation)
                    .map_err(|e| decode_err(error_code, e))?
                    .claims;
                claims.validate()?;
                Ok(Self::Auth(claims))
            }
            JwtTyp::Resource => Err(AAuthError::from(TokenError::new(
                typ.verify_error_code(),
                format!("Unsupported JWT typ for verification: {typ}"),
            ))),
        }
    }

    pub fn iss(&self) -> &str {
        match self {
            Self::Agent(c) => &c.iss,
            Self::Auth(c) => &c.iss,
        }
    }

    pub fn dwk(&self) -> &str {
        match self {
            Self::Agent(c) => &c.dwk,
            Self::Auth(c) => &c.dwk,
        }
    }

    pub fn exp(&self) -> i64 {
        match self {
            Self::Agent(c) => c.exp,
            Self::Auth(c) => c.exp,
        }
    }

    pub fn cnf_jwk(&self) -> &OkpJwk {
        match self {
            Self::Agent(c) => &c.cnf.jwk,
            Self::Auth(c) => &c.cnf.jwk,
        }
    }

    pub fn token_type(&self) -> &'static str {
        match self {
            Self::Agent(_) => "agent",
            Self::Auth(_) => "auth",
        }
    }

    /// Agent identifier from an agent JWT, when the verified token is an agent token.
    pub fn agent_identifier(&self) -> Option<&str> {
        match self {
            Self::Agent(c) => Some(c.identifier()),
            Self::Auth(_) => None,
        }
    }
}

/// Decode a resource token payload without signature verification.
pub fn decode_resource_token_unverified(jwt: &str) -> Result<ResourceClaims> {
    let typ = JwtTyp::from_jwt(jwt)?;
    if typ != JwtTyp::Resource {
        return Err(AAuthError::from(TokenError::new(
            typ.verify_error_code(),
            format!("expected resource JWT, got {typ}"),
        )));
    }
    decode_unverified::<ResourceClaims>(jwt)
        .map(|data| data.claims)
        .map_err(|e| decode_err(typ.verify_error_code(), e))
}

fn decode_err(code: &str, err: AAuthError) -> AAuthError {
    AAuthError::from(TokenError::new(code, format!("JWT decode failed: {err}")))
}
