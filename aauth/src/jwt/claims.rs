use crate::error::{Result, VerifyError};

pub use crate::protocol::{
    ActClaim, AgentClaims, AuthClaims, CnfClaim, PublicJwk, ResourceClaims,
    ResourceInteractionClaim, SigningJwk,
};

use super::decode::{decode_unverified, decode_verified, jwt_header, verified_validation};
use crate::protocol::JwtTyp;

impl AuthClaims {
    pub fn validate(&self) -> Result<()> {
        if self.sub.is_none() && self.scope.is_none() {
            return Err(VerifyError::token(
                JwtTyp::Auth.verify_error_code(),
                "at least one of sub or scope must be present",
            )
            .into());
        }
        Ok(())
    }
}

/// Parsed AAuth JWT claims, tagged by header `typ` (signature not necessarily verified).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ParsedToken {
    Agent(AgentClaims),
    Auth(AuthClaims),
    Resource(ResourceClaims),
}

impl ParsedToken {
    /// Decode claims from a compact JWT without verifying the signature.
    pub fn parse(jwt: &str) -> Result<Self> {
        let header = jwt_header(jwt)?;
        let error_code = header.typ.verify_error_code();

        match header.typ {
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
            JwtTyp::Resource => decode_unverified::<ResourceClaims>(jwt)
                .map(|data| Self::Resource(data.claims))
                .map_err(|e| decode_err(error_code, e)),
        }
    }

    /// Verify the JWT signature with `key` and return typed claims.
    pub fn verify_with_key(jwt: &str, key: &jsonwebtoken::DecodingKey) -> Result<Self> {
        let header = jwt_header(jwt)?;
        let error_code = header.typ.verify_error_code();
        let validation = verified_validation(header.alg);

        match header.typ {
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
            JwtTyp::Resource => decode_verified::<ResourceClaims>(jwt, key, &validation)
                .map(|data| Self::Resource(data.claims))
                .map_err(|e| decode_err(error_code, e)),
        }
    }

    pub fn iss(&self) -> &str {
        match self {
            Self::Agent(c) => &c.iss,
            Self::Auth(c) => &c.iss,
            Self::Resource(c) => &c.iss,
        }
    }

    pub fn dwk(&self) -> &str {
        match self {
            Self::Agent(c) => &c.dwk,
            Self::Auth(c) => &c.dwk,
            Self::Resource(c) => &c.dwk,
        }
    }

    pub fn exp(&self) -> i64 {
        match self {
            Self::Agent(c) => c.exp,
            Self::Auth(c) => c.exp,
            Self::Resource(c) => c.exp as i64,
        }
    }

    pub fn cnf_jwk(&self) -> Option<&PublicJwk> {
        match self {
            Self::Agent(c) => Some(&c.cnf.jwk),
            Self::Auth(c) => Some(&c.cnf.jwk),
            Self::Resource(_) => None,
        }
    }

    pub fn token_type(&self) -> &'static str {
        match self {
            Self::Agent(_) => "agent",
            Self::Auth(_) => "auth",
            Self::Resource(_) => "resource",
        }
    }

    pub fn agent_identifier(&self) -> Option<&str> {
        match self {
            Self::Agent(c) => Some(c.identifier()),
            Self::Auth(_) | Self::Resource(_) => None,
        }
    }

    pub fn as_agent(&self) -> Option<&AgentClaims> {
        match self {
            Self::Agent(c) => Some(c),
            _ => None,
        }
    }

    pub fn as_auth(&self) -> Option<&AuthClaims> {
        match self {
            Self::Auth(c) => Some(c),
            _ => None,
        }
    }

    pub fn as_resource(&self) -> Option<&ResourceClaims> {
        match self {
            Self::Resource(c) => Some(c),
            _ => None,
        }
    }
}

fn decode_err(code: &str, err: crate::error::AAuthError) -> crate::error::AAuthError {
    VerifyError::token(code, format!("JWT decode failed: {err}")).into()
}
