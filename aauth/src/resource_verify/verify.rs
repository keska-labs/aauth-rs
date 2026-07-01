use std::sync::Arc;

use jsonwebtoken::{DecodingKey, decode_header};

use crate::error::{AAuthError, Result, TokenError};
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
    let error_code = match typ {
        JwtTyp::Agent | JwtTyp::Auth => typ.verify_error_code(),
        JwtTyp::Resource => {
            return Err(TokenError::new(
                typ.verify_error_code(),
                format!("Unsupported JWT typ for verification: {typ}"),
            )
            .into());
        }
    };

    let claims = VerifiedToken::decode_unverified(&options.jwt)?;

    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs() as i64;
    if claims.exp() < now - CLOCK_SKEW {
        return Err(TokenError::new(error_code, "Token has expired").into());
    }

    let cnf_thumbprint = jwk_thumbprint(claims.cnf_jwk())?;
    if cnf_thumbprint != options.http_signature_thumbprint {
        return Err(TokenError::new(
            "key_binding_failed",
            "cnf.jwk thumbprint does not match HTTP signature key",
        )
        .into());
    }

    let decoding_key = fetch_decoding_key(
        claims.iss(),
        claims.dwk(),
        error_code,
        &options.fetcher,
        &options.jwt,
    )
    .await?;

    VerifiedToken::decode_verified(&options.jwt, &decoding_key).map_err(|e| {
        if let AAuthError::Token { code, message } = e {
            TokenError::new(code, message)
        } else {
            TokenError::new(
                error_code,
                format!("JWT signature verification failed: {e}"),
            )
        }
        .into()
    })
}

pub async fn verify_resource_token(options: VerifyResourceTokenOptions) -> Result<ResourceClaims> {
    let error_code = JwtTyp::Resource.verify_error_code();
    let claims = decode_resource_token_unverified(&options.jwt)?;

    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs() as i64;
    if (claims.exp as i64) < now - CLOCK_SKEW {
        return Err(TokenError::new(error_code, "Resource token has expired").into());
    }

    if claims.dwk != "aauth-resource.json" {
        return Err(TokenError::new(error_code, "invalid resource token dwk").into());
    }

    if let Some(expected) = &options.expected_agent {
        if &claims.agent != expected {
            return Err(TokenError::new(error_code, "resource token agent mismatch").into());
        }
    }

    if let Some(expected_jkt) = &options.expected_agent_jkt {
        if &claims.agent_jkt != expected_jkt {
            return Err(TokenError::new(error_code, "resource token agent_jkt mismatch").into());
        }
    }

    let decoding_key = fetch_decoding_key(
        &claims.iss,
        &claims.dwk,
        error_code,
        &options.fetcher,
        &options.jwt,
    )
    .await?;

    jsonwebtoken::decode::<ResourceClaims>(
        &options.jwt,
        &decoding_key,
        &crate::jwt::verified_validation(),
    )
    .map(|data| data.claims)
    .map_err(|e| {
        TokenError::new(
            error_code,
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
        return Err(
            TokenError::new(JwtTyp::Auth.verify_error_code(), "auth token aud mismatch").into(),
        );
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
            return Err(
                TokenError::new(JwtTyp::Auth.verify_error_code(), "expected auth token").into(),
            );
        }
    };

    verify_auth_token_binding(&auth, resource_url)?;
    if auth.agent != agent_sub {
        return Err(TokenError::new(
            JwtTyp::Auth.verify_error_code(),
            "auth token agent mismatch",
        )
        .into());
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
            return Err(TokenError::new(
                JwtTyp::Resource.verify_error_code(),
                "resource token iss mismatch",
            )
            .into());
        }
        Ok(claims)
    })
}

async fn fetch_decoding_key(
    iss: &str,
    dwk: &str,
    error_code: &str,
    fetcher: &Arc<dyn MetadataFetcher>,
    jwt: &str,
) -> Result<DecodingKey> {
    let jwks_uri = fetcher
        .resolve_jwks_uri(iss, dwk)
        .await
        .map_err(|e| match e {
            AAuthError::Token { code, message } => TokenError::new(code, message),
            other => TokenError::new("metadata_fetch_failed", other.to_string()),
        })?;

    let jwks = fetcher.fetch_jwks(&jwks_uri).await.map_err(|e| {
        TokenError::new(
            error_code,
            format!("Failed to fetch JWKS from {jwks_uri}: {e}"),
        )
    })?;

    let header = decode_header(jwt).map_err(|e| AAuthError::Message(e.to_string()))?;
    let kid = header
        .kid
        .ok_or_else(|| AAuthError::Message("missing kid".into()))?;

    let jwk = jwks
        .find(&kid)
        .ok_or_else(|| AAuthError::Message(format!("unknown kid: {kid}")))?;

    DecodingKey::from_jwk(jwk).map_err(|e| AAuthError::Message(e.to_string()))
}
