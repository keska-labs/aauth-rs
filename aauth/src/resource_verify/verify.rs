use std::sync::Arc;

use jsonwebtoken::{DecodingKey, decode_header};

use crate::error::{JwtError, Result, VerifyError, VerifyReason};
use crate::jwt::{
    AuthClaims, ResourceClaims, VerifiedToken, decode_resource_token_unverified, jwk_thumbprint,
};
use crate::metadata::MetadataFetcher;
use crate::protocol::JwtTyp;

const CLOCK_SKEW: i64 = 60;

pub struct VerifyTokenOptions {
    pub jwt: String,
    pub http_signature_thumbprint: String,
    pub fetcher: Arc<dyn MetadataFetcher>,
}

pub struct VerifyResourceTokenOptions {
    pub jwt: String,
    pub expected_agent: Option<String>,
    pub expected_agent_jkt: Option<String>,
    pub fetcher: Arc<dyn MetadataFetcher>,
}

pub async fn verify_token(options: VerifyTokenOptions) -> Result<VerifiedToken> {
    let typ = JwtTyp::from_jwt(&options.jwt)?;
    match typ {
        JwtTyp::Agent | JwtTyp::Auth => {}
        JwtTyp::Resource => {
            return Err(VerifyError::Invalid {
                typ,
                reason: VerifyReason::UnsupportedTyp,
            }
            .into());
        }
    }

    let claims = VerifiedToken::decode_unverified(&options.jwt)?;

    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs() as i64;
    if claims.exp() < now - CLOCK_SKEW {
        return Err(VerifyError::Expired { typ }.into());
    }

    let cnf_thumbprint = jwk_thumbprint(claims.cnf_jwk())?;
    if cnf_thumbprint != options.http_signature_thumbprint {
        return Err(VerifyError::KeyBindingFailed.into());
    }

    let decoding_key =
        fetch_decoding_key(claims.iss(), claims.dwk(), &options.fetcher, &options.jwt).await?;

    VerifiedToken::decode_verified(&options.jwt, &decoding_key).map_err(|e| match e {
        crate::error::AAuthError::Verify(v) => v.into(),
        crate::error::AAuthError::Jwt(j) => VerifyError::Jwt(j).into(),
        other => VerifyError::token(
            typ.verify_error_code(),
            format!("JWT signature verification failed: {other}"),
        )
        .into(),
    })
}

pub async fn verify_resource_token(options: VerifyResourceTokenOptions) -> Result<ResourceClaims> {
    let claims = decode_resource_token_unverified(&options.jwt)?;

    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs() as i64;
    if (claims.exp as i64) < now - CLOCK_SKEW {
        return Err(VerifyError::Expired {
            typ: JwtTyp::Resource,
        }
        .into());
    }

    if claims.dwk != "aauth-resource.json" {
        return Err(VerifyError::Invalid {
            typ: JwtTyp::Resource,
            reason: VerifyReason::InvalidDwk,
        }
        .into());
    }

    if let Some(expected) = &options.expected_agent {
        if &claims.agent != expected {
            return Err(VerifyError::AgentMismatch.into());
        }
    }

    if let Some(expected_jkt) = &options.expected_agent_jkt {
        if &claims.agent_jkt != expected_jkt {
            return Err(VerifyError::AgentJktMismatch.into());
        }
    }

    let decoding_key =
        fetch_decoding_key(&claims.iss, &claims.dwk, &options.fetcher, &options.jwt).await?;

    jsonwebtoken::decode::<ResourceClaims>(
        &options.jwt,
        &decoding_key,
        &crate::jwt::verified_validation(),
    )
    .map(|data| data.claims)
    .map_err(|e| {
        VerifyError::token(
            JwtTyp::Resource.verify_error_code(),
            format!("Resource token signature verification failed: {e}"),
        )
        .into()
    })
}

fn normalize_server_url(url: &str) -> String {
    url.trim_end_matches('/').to_lowercase()
}

/// Verify auth token `aud` binding for resource access.
pub fn verify_auth_token_binding(auth: &AuthClaims, resource_url: &str) -> Result<()> {
    if normalize_server_url(&auth.aud) != normalize_server_url(resource_url) {
        return Err(VerifyError::AudMismatch.into());
    }
    Ok(())
}

/// Verify an auth token returned from token exchange before caching.
pub async fn verify_client_auth_token(
    jwt: &str,
    resource_url: &str,
    agent_sub: &str,
    agent_jkt: &str,
    fetcher: Arc<dyn MetadataFetcher>,
) -> Result<AuthClaims> {
    let verified = verify_token(VerifyTokenOptions {
        jwt: jwt.to_string(),
        http_signature_thumbprint: agent_jkt.to_string(),
        fetcher,
    })
    .await?;

    let auth = match verified {
        VerifiedToken::Auth(c) => c,
        _ => {
            return Err(VerifyError::Invalid {
                typ: JwtTyp::Auth,
                reason: VerifyReason::ExpectedAuth,
            }
            .into());
        }
    };

    verify_auth_token_binding(&auth, resource_url)?;
    if auth.agent != agent_sub {
        return Err(VerifyError::AgentMismatch.into());
    }

    Ok(auth)
}

/// Verify a resource token from a `401` challenge before token exchange.
pub async fn verify_resource_challenge(
    jwt: &str,
    resource_url: &str,
    agent_sub: &str,
    agent_jkt: &str,
    fetcher: Arc<dyn MetadataFetcher>,
) -> Result<ResourceClaims> {
    verify_resource_token(VerifyResourceTokenOptions {
        jwt: jwt.to_string(),
        expected_agent: Some(agent_sub.to_string()),
        expected_agent_jkt: Some(agent_jkt.to_string()),
        fetcher,
    })
    .await
    .and_then(|claims| {
        if normalize_server_url(&claims.iss) != normalize_server_url(resource_url) {
            return Err(VerifyError::IssMismatch.into());
        }
        Ok(claims)
    })
}

async fn fetch_decoding_key(
    iss: &str,
    dwk: &str,
    fetcher: &Arc<dyn MetadataFetcher>,
    jwt: &str,
) -> Result<DecodingKey> {
    let jwks_uri = fetcher.resolve_jwks_uri(iss, dwk).await?;
    let jwks = fetcher.fetch_jwks(&jwks_uri).await?;

    let header = decode_header(jwt).map_err(JwtError::Decode)?;
    let kid = header.kid.ok_or(VerifyError::MissingKid)?;

    let jwk = jwks
        .find(&kid)
        .ok_or_else(|| VerifyError::UnknownKid(kid.clone()))?;

    DecodingKey::from_jwk(jwk)
        .map_err(JwtError::Decode)
        .map_err(Into::into)
}
