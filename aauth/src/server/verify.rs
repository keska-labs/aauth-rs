use std::sync::Arc;

use serde_json::Value;

use crate::error::{AAuthError, Result, TokenError};
use crate::jwt::{decode_jwt_payload, jwk_thumbprint};
use crate::metadata::MetadataFetcher;
use crate::types::{JwtTyp, VerifiedAgentToken, VerifiedAuthToken, VerifiedToken};

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

    let claims = decode_jwt_payload(&options.jwt)?;

    let iss = claim_string(&claims, "iss", error_code)?;
    let iat = claim_i64(&claims, "iat", error_code)?;
    let exp = claim_i64(&claims, "exp", error_code)?;
    let dwk = claim_string(&claims, "dwk", error_code)?;

    let cnf = claims
        .get("cnf")
        .and_then(|v| v.get("jwk"))
        .ok_or_else(|| {
            AAuthError::from(TokenError::new(
                error_code,
                "Missing required claim: cnf.jwk",
            ))
        })?;

    match typ {
        JwtTyp::Agent => {
            claim_string(&claims, "sub", error_code)?;
        }
        JwtTyp::Auth => {
            if claims.get("aud").is_none() {
                return Err(TokenError::new(error_code, "Missing required claim: aud").into());
            }
            if claims.get("agent").is_none() {
                return Err(TokenError::new(error_code, "Missing required claim: agent").into());
            }
        }
        JwtTyp::Resource => unreachable!("handled above"),
    }

    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs() as i64;
    if exp < now - CLOCK_SKEW {
        return Err(TokenError::new(error_code, "Token has expired").into());
    }

    let cnf_thumbprint = jwk_thumbprint(cnf)?;
    if cnf_thumbprint != options.http_signature_thumbprint {
        return Err(TokenError::new(
            "key_binding_failed",
            "cnf.jwk thumbprint does not match HTTP signature key",
        )
        .into());
    }

    let jwks_uri = options
        .fetcher
        .resolve_jwks_uri(&iss, &dwk)
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

    verify_jwt_signature(&options.jwt, &jwks, exp, iat).map_err(|e| {
        TokenError::new(
            error_code,
            format!("JWT signature verification failed: {e}"),
        )
    })?;

    match typ {
        JwtTyp::Agent => Ok(VerifiedToken::Agent(VerifiedAgentToken {
            iss,
            dwk,
            sub: claim_string(&claims, "sub", error_code)?,
            cnf_jwk: cnf.clone(),
            iat,
            exp,
        })),
        JwtTyp::Auth => Ok(VerifiedToken::Auth(VerifiedAuthToken {
            iss,
            dwk,
            aud: claims.get("aud").cloned().unwrap_or(Value::Null),
            agent: claim_string(&claims, "agent", error_code)?,
            cnf_jwk: cnf.clone(),
            sub: claims
                .get("sub")
                .and_then(|v| v.as_str())
                .map(str::to_string),
            scope: claims
                .get("scope")
                .and_then(|v| v.as_str())
                .map(str::to_string),
            tenant: claims
                .get("tenant")
                .and_then(|v| v.as_str())
                .map(str::to_string),
            iat,
            exp,
        })),
        JwtTyp::Resource => unreachable!("handled above"),
    }
}

fn claim_string(claims: &Value, key: &str, code: &str) -> Result<String> {
    claims
        .get(key)
        .and_then(|v| v.as_str())
        .map(str::to_string)
        .ok_or_else(|| AAuthError::from(TokenError::new(code, format!("Missing required claim: {key}"))))
}

fn claim_i64(claims: &Value, key: &str, code: &str) -> Result<i64> {
    claims
        .get(key)
        .and_then(|v| v.as_i64())
        .ok_or_else(|| AAuthError::from(TokenError::new(code, format!("Missing required claim: {key}"))))
}

fn verify_jwt_signature(jwt: &str, jwks: &Value, _exp: i64, _iat: i64) -> Result<()> {
    use jsonwebtoken::{decode, decode_header, Algorithm, Validation};

    let header = decode_header(jwt).map_err(|e| AAuthError::Message(e.to_string()))?;
    let kid = header
        .kid
        .ok_or_else(|| AAuthError::Message("missing kid".into()))?;

    let keys = jwks
        .get("keys")
        .and_then(|v| v.as_array())
        .ok_or_else(|| AAuthError::Message("invalid JWKS".into()))?;

    let jwk = keys
        .iter()
        .find(|k| k.get("kid").and_then(|v| v.as_str()) == Some(&kid))
        .ok_or_else(|| AAuthError::Message(format!("unknown kid: {kid}")))?;

    let decoding_key = jwk_to_decoding_key(jwk)?;
    let mut validation = Validation::new(Algorithm::EdDSA);
    validation.set_audience(&[] as &[&str]);
    validation.validate_aud = false;
    validation.leeway = CLOCK_SKEW as u64;

    decode::<Value>(jwt, &decoding_key, &validation)
        .map_err(|e| AAuthError::Message(e.to_string()))?;
    Ok(())
}

fn jwk_to_decoding_key(jwk: &Value) -> Result<jsonwebtoken::DecodingKey> {
    let x = jwk
        .get("x")
        .and_then(|v| v.as_str())
        .ok_or_else(|| AAuthError::Message("JWK missing x".into()))?;
    jsonwebtoken::DecodingKey::from_ed_components(x).map_err(|e| AAuthError::Message(e.to_string()))
}
