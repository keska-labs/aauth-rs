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

/// Verify an agent or auth JWT presented with an HTTP Message Signature (`cnf` ↔ thumbprint).
///
/// Spec: `draft-hardt-oauth-aauth-protocol.md#agent-tokens` (Agent Token Verification),
/// `#auth-token-verification` (JWT trust + request-context `cnf` binding),
/// `#jwks-discovery`
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

/// Verify a resource JWT (`typ=aa-resource+jwt`).
///
/// Spec: `draft-hardt-oauth-aauth-protocol.md#resource-token-structure`,
/// Resource Token Verification under `#resource-tokens`
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
///
/// Spec: `draft-hardt-oauth-aauth-protocol.md#auth-token-verification`
/// (request-context binding)
pub fn verify_auth_token_binding(auth: &AuthClaims, resource_url: &str) -> Result<()> {
    if normalize_server_url(&auth.aud) != normalize_server_url(resource_url) {
        return Err(VerifyError::AudMismatch.into());
    }
    Ok(())
}

/// MUST claim checks for an auth token returned from token exchange,
/// without JWT signature verification.
///
/// Spec: `draft-hardt-oauth-aauth-protocol.md#auth-token-response-verification`
/// (steps 2–6)
fn verify_client_auth_token_claims(
    auth: &AuthClaims,
    resource_url: &str,
    resource_token_aud: &str,
    agent_sub: &str,
    agent_jkt: &str,
) -> Result<()> {
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs() as i64;
    if auth.exp < now - CLOCK_SKEW {
        return Err(VerifyError::Expired { typ: JwtTyp::Auth }.into());
    }

    // Step 2: iss matches the resource token's aud.
    if normalize_server_url(&auth.iss) != normalize_server_url(resource_token_aud) {
        return Err(VerifyError::IssMismatch.into());
    }

    // Step 3: aud matches the resource the agent intends to access.
    verify_auth_token_binding(auth, resource_url)?;

    // Step 4: cnf.jwk matches the agent's signing key.
    let cnf_thumbprint = jwk_thumbprint(&auth.cnf.jwk)?;
    if cnf_thumbprint != agent_jkt {
        return Err(VerifyError::KeyBindingFailed.into());
    }

    // Step 5: agent matches the agent's own identifier.
    if auth.agent != agent_sub {
        return Err(VerifyError::AgentMismatch.into());
    }

    // Step 6: if act is present, act.agent must be a non-empty AAuth agent id.
    if let Some(act) = &auth.act {
        if act.agent.is_empty() || !act.agent.starts_with("aauth:") {
            return Err(VerifyError::token(
                JwtTyp::Auth.verify_error_code(),
                "act.agent must be a non-empty aauth: agent identifier",
            )
            .into());
        }
    }

    Ok(())
}

/// Verify an auth token returned from token exchange before caching.
///
/// Always applies MUST claim checks. When `verify_signature` is `true` (spec SHOULD),
/// also verifies the JWT signature via the issuer JWKS.
///
/// Spec: `draft-hardt-oauth-aauth-protocol.md#auth-token-response-verification`
pub async fn verify_client_auth_token<F: MetadataFetcher>(
    jwt: &str,
    resource_url: &str,
    resource_token_aud: &str,
    agent_sub: &str,
    agent_jkt: &str,
    fetcher: F,
    verify_signature: bool,
) -> Result<AuthClaims> {
    let parsed = ParsedToken::parse(jwt)?;
    let auth = match parsed {
        ParsedToken::Auth(c) => c,
        _ => {
            return Err(VerifyError::Invalid {
                typ: JwtTyp::Auth,
                reason: VerifyReason::ExpectedAuth,
            }
            .into());
        }
    };

    verify_client_auth_token_claims(
        &auth,
        resource_url,
        resource_token_aud,
        agent_sub,
        agent_jkt,
    )?;

    if verify_signature {
        let decoding_key = fetch_decoding_key(&auth.iss, &auth.dwk, &fetcher, jwt).await?;
        match ParsedToken::verify_with_key(jwt, &decoding_key)? {
            ParsedToken::Auth(c) => Ok(c),
            _ => Err(VerifyError::Invalid {
                typ: JwtTyp::Auth,
                reason: VerifyReason::ExpectedAuth,
            }
            .into()),
        }
    } else {
        Ok(auth)
    }
}

/// Verify a resource token from a `401` challenge before token exchange.
///
/// Spec: `draft-hardt-oauth-aauth-protocol.md#resource-challenge-verification`,
/// `#requirement-auth-token`
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

/// Resolve issuer JWKS and select the key by JWT `kid`.
///
/// Spec: `draft-hardt-oauth-aauth-protocol.md#jwks-discovery`
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
