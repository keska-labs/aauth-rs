use jsonwebtoken::DecodingKey;

use crate::error::{Result, VerifyError, VerifyReason};
use crate::http_util::normalize_server_url;
use crate::jwt::{AuthClaims, ParsedToken, ResourceClaims, jwk_thumbprint, jwt_header};
use crate::metadata::MetadataFetcher;
use crate::protocol::JwtTyp;

const CLOCK_SKEW: i64 = 60;

pub struct VerifyTokenOptions<F> {
    pub jwt: String,
    pub http_signature_thumbprint: String,
    pub fetcher: F,
}

pub struct VerifyResourceTokenOptions<F> {
    pub jwt: String,
    pub expected_agent: Option<String>,
    pub expected_agent_jkt: Option<String>,
    pub fetcher: F,
}

pub async fn verify_token<F: MetadataFetcher>(
    options: VerifyTokenOptions<F>,
) -> Result<ParsedToken> {
    let parsed = ParsedToken::parse(&options.jwt)?;
    let typ = match &parsed {
        ParsedToken::Agent(_) => JwtTyp::Agent,
        ParsedToken::Auth(_) => JwtTyp::Auth,
        ParsedToken::Resource(_) => {
            return Err(VerifyError::Invalid {
                typ: JwtTyp::Resource,
                reason: VerifyReason::UnsupportedTyp,
            }
            .into());
        }
    };

    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs() as i64;
    if parsed.exp() < now - CLOCK_SKEW {
        return Err(VerifyError::Expired { typ }.into());
    }

    let cnf_jwk = parsed.cnf_jwk().ok_or(VerifyError::KeyBindingFailed)?;
    let cnf_thumbprint = jwk_thumbprint(cnf_jwk)?;
    if cnf_thumbprint != options.http_signature_thumbprint {
        return Err(VerifyError::KeyBindingFailed.into());
    }

    let decoding_key =
        fetch_decoding_key(parsed.iss(), parsed.dwk(), &options.fetcher, &options.jwt).await?;

    ParsedToken::verify_with_key(&options.jwt, &decoding_key).map_err(|e| match e {
        crate::error::AAuthError::Verify(v) => v.into(),
        crate::error::AAuthError::Jwt(j) => VerifyError::Jwt(j).into(),
        other => VerifyError::token(
            typ.verify_error_code(),
            format!("JWT signature verification failed: {other}"),
        )
        .into(),
    })
}

pub async fn verify_resource_token<F: MetadataFetcher>(
    options: VerifyResourceTokenOptions<F>,
) -> Result<ResourceClaims> {
    let parsed = ParsedToken::parse(&options.jwt)?;
    let claims = match parsed {
        ParsedToken::Resource(c) => c,
        ParsedToken::Agent(_) => {
            return Err(VerifyError::Invalid {
                typ: JwtTyp::Resource,
                reason: VerifyReason::WrongTyp,
            }
            .into());
        }
        ParsedToken::Auth(_) => {
            return Err(VerifyError::Invalid {
                typ: JwtTyp::Resource,
                reason: VerifyReason::WrongTyp,
            }
            .into());
        }
    };

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

    match ParsedToken::verify_with_key(&options.jwt, &decoding_key)? {
        ParsedToken::Resource(c) => Ok(c),
        _ => Err(VerifyError::token(
            JwtTyp::Resource.verify_error_code(),
            "Resource token signature verification failed: unexpected typ",
        )
        .into()),
    }
}

/// Verify auth token `aud` binding for resource access.
pub fn verify_auth_token_binding(auth: &AuthClaims, resource_url: &str) -> Result<()> {
    if normalize_server_url(&auth.aud) != normalize_server_url(resource_url) {
        return Err(VerifyError::AudMismatch.into());
    }
    Ok(())
}

/// Verify an auth token returned from token exchange before caching.
pub async fn verify_client_auth_token<F: MetadataFetcher>(
    jwt: &str,
    resource_url: &str,
    agent_sub: &str,
    agent_jkt: &str,
    fetcher: F,
) -> Result<AuthClaims> {
    let verified = verify_token(VerifyTokenOptions {
        jwt: jwt.to_string(),
        http_signature_thumbprint: agent_jkt.to_string(),
        fetcher,
    })
    .await?;

    let auth = match verified {
        ParsedToken::Auth(c) => c,
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
pub async fn verify_resource_challenge<F: MetadataFetcher>(
    jwt: &str,
    resource_url: &str,
    agent_sub: &str,
    agent_jkt: &str,
    fetcher: F,
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

async fn fetch_decoding_key<F: MetadataFetcher>(
    iss: &str,
    dwk: &str,
    fetcher: &F,
    jwt: &str,
) -> Result<DecodingKey> {
    let jwks_uri = fetcher.resolve_jwks_uri(iss, dwk).await?;
    let jwks = fetcher.fetch_jwks(&jwks_uri).await?;

    let header = jwt_header(jwt)?;
    let kid = header.kid.ok_or(VerifyError::MissingKid)?;

    let jwk = jwks
        .find(&kid)
        .ok_or_else(|| VerifyError::UnknownKid(kid.clone()))?;

    DecodingKey::from_jwk(jwk)
        .map_err(crate::error::JwtError::Decode)
        .map_err(Into::into)
}
