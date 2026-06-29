use serde::{Deserialize, Serialize};

use crate::error::{AAuthError, Result, TokenError};
use crate::types::{JwtTyp, Mission};

use super::decode::{decode_unverified, decode_verified, verified_validation};

/// https://github.com/dickhardt/AAuth/blob/main/draft-hardt-oauth-aauth-protocol.md#jwks-discovery-and-caching-jwks-discovery
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct OkpJwk {
    pub kty: String,
    pub crv: String,
    pub x: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub kid: Option<String>,
}

/// https://github.com/dickhardt/AAuth/blob/main/draft-hardt-oauth-aauth-protocol.md#keying-material
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct OkpSigningJwk {
    pub kty: String,
    pub crv: String,
    pub x: String,
    pub d: String,
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

/// https://github.com/dickhardt/AAuth/blob/main/draft-hardt-oauth-aauth-protocol.md#agent-token-structure
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CnfClaim {
    pub jwk: OkpJwk,
}

/// https://github.com/dickhardt/AAuth/blob/main/draft-hardt-oauth-aauth-protocol.md#delegation-chain
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ActClaim {
    pub agent: String,
}

/// https://github.com/dickhardt/AAuth/blob/main/draft-hardt-oauth-aauth-protocol.md#agent-token-agent-tokens
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AgentClaims {
    pub iss: String,
    pub dwk: String,
    pub sub: String,
    pub jti: String,
    pub cnf: CnfClaim,
    pub iat: i64,
    pub exp: i64,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub ps: Option<String>,
}

impl AgentClaims {
    /// Agent identifier (`aauth:local@domain`) — use for resource/auth token `agent` claims.
    pub fn identifier(&self) -> &str {
        &self.sub
    }
}

/// https://github.com/dickhardt/AAuth/blob/main/draft-hardt-oauth-aauth-protocol.md#auth-token-auth-tokens
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AuthClaims {
    pub iss: String,
    pub dwk: String,
    pub aud: String,
    pub jti: String,
    pub agent: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub act: Option<ActClaim>,
    pub cnf: CnfClaim,
    pub iat: i64,
    pub exp: i64,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub sub: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub scope: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub tenant: Option<String>,
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

/// https://github.com/dickhardt/AAuth/blob/main/draft-hardt-oauth-aauth-protocol.md#resource-token-structure
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ResourceClaims {
    pub iss: String,
    pub dwk: String,
    pub aud: String,
    pub jti: String,
    pub agent: String,
    pub agent_jkt: String,
    pub iat: u64,
    pub exp: u64,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub scope: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub mission: Option<Mission>,
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
