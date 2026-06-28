use std::sync::Arc;

use jsonwebtoken::{decode_header, jwk::JwkSet, DecodingKey};

use crate::error::{AAuthError, Result, TokenError};
use crate::jwt::{jwk_thumbprint, VerifiedToken};
use crate::metadata::MetadataFetcher;
use crate::types::JwtTyp;

const CLOCK_SKEW: i64 = 60;

pub struct VerifyTokenOptions<F: MetadataFetcher> {
    pub jwt: String,
    pub http_signature_thumbprint: String,
    pub fetcher: Arc<F>,
}

pub async fn verify_token<F: MetadataFetcher>(
    options: VerifyTokenOptions<F>,
) -> Result<VerifiedToken> {
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

    let jwks_uri = options
        .fetcher
        .resolve_jwks_uri(claims.iss(), claims.dwk())
        .await
        .map_err(|e| match e {
            AAuthError::Token { code, message } => TokenError::new(code, message),
            other => TokenError::new("metadata_fetch_failed", other.to_string()),
        })?;

    let jwks = options.fetcher.fetch_jwks(&jwks_uri).await.map_err(|e| {
        TokenError::new(
            error_code,
            format!("Failed to fetch JWKS from {jwks_uri}: {e}"),
        )
    })?;

    let jwks: JwkSet = serde_json::from_value(jwks).map_err(|e| {
        TokenError::new(error_code, format!("invalid JWKS from {jwks_uri}: {e}"))
    })?;

    let header = decode_header(&options.jwt).map_err(|e| AAuthError::Message(e.to_string()))?;
    let kid = header
        .kid
        .ok_or_else(|| AAuthError::Message("missing kid".into()))?;

    let jwk = jwks
        .find(&kid)
        .ok_or_else(|| AAuthError::Message(format!("unknown kid: {kid}")))?;

    let decoding_key = DecodingKey::from_jwk(jwk).map_err(|e| AAuthError::Message(e.to_string()))?;

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
