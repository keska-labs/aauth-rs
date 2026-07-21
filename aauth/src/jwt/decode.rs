use jsonwebtoken::{
    Algorithm, DecodingKey, TokenData, Validation, dangerous::insecure_decode, decode,
    decode_header,
};
use serde::de::DeserializeOwned;

use crate::error::{JwtError, Result};
use crate::protocol::JwtTyp;

const CLOCK_SKEW: u64 = 60;

/// Parsed JWT header fields used for AAuth verify.
#[derive(Debug, Clone)]
pub struct JwtHeaderParts {
    pub typ: JwtTyp,
    pub alg: Algorithm,
    pub kid: Option<String>,
}

/// Read `typ`, `alg`, and `kid` from a compact JWT.
///
/// Spec: agent/auth/resource token headers MUST NOT accept `alg: none`
/// (`draft-hardt-oauth-aauth-protocol.md#agent-tokens`).
pub fn jwt_header(jwt: &str) -> Result<JwtHeaderParts> {
    reject_alg_none(jwt)?;
    let header = decode_header(jwt).map_err(JwtError::Decode)?;
    let typ_str = header.typ.ok_or(JwtError::MissingTyp)?;
    let typ = typ_str.parse().map_err(|_| JwtError::UnknownTyp(typ_str))?;
    Ok(JwtHeaderParts {
        typ,
        alg: header.alg,
        kid: header.kid,
    })
}

//TODO: Review if needed, I think this is handled by jwt header parsing above.
fn reject_alg_none(jwt: &str) -> Result<()> {
    use base64::Engine;
    use base64::engine::general_purpose::URL_SAFE_NO_PAD;

    let header_b64 = jwt.split('.').next().ok_or(JwtError::AlgNone)?;
    let bytes = URL_SAFE_NO_PAD
        .decode(header_b64)
        .map_err(|_| JwtError::AlgNone)?;
    let value: serde_json::Value = serde_json::from_slice(&bytes).map_err(|_| JwtError::AlgNone)?;
    let alg = value
        .get("alg")
        .and_then(|v| v.as_str())
        .unwrap_or_default();
    if alg.eq_ignore_ascii_case("none") {
        return Err(JwtError::AlgNone.into());
    }
    Ok(())
}

pub(crate) fn decode_unverified<T: DeserializeOwned>(jwt: &str) -> Result<TokenData<T>> {
    insecure_decode(jwt)
        .map_err(JwtError::Decode)
        .map_err(Into::into)
}

pub(crate) fn decode_verified<T: DeserializeOwned>(
    jwt: &str,
    key: &DecodingKey,
    validation: &Validation,
) -> Result<TokenData<T>> {
    decode(jwt, key, validation)
        .map_err(JwtError::Decode)
        .map_err(Into::into)
}

/// Validation for a verified JWT. `alg` must match the token header (jsonwebtoken 10
/// rejects mixed algorithm families in one [`Validation`]).
pub fn verified_validation(alg: Algorithm) -> Validation {
    let mut validation = Validation::new(alg);
    validation.validate_aud = false;
    validation.leeway = CLOCK_SKEW;
    validation
}

/// Build [`verified_validation`] from the JWT `alg` header.
pub fn verified_validation_for_jwt(jwt: &str) -> Result<Validation> {
    Ok(verified_validation(jwt_header(jwt)?.alg))
}
