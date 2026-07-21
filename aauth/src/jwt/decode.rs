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
pub fn jwt_header(jwt: &str) -> Result<JwtHeaderParts> {
    let header = decode_header(jwt).map_err(JwtError::Decode)?;
    let typ_str = header.typ.ok_or(JwtError::MissingTyp)?;
    let typ = typ_str.parse().map_err(|_| JwtError::UnknownTyp(typ_str))?;
    Ok(JwtHeaderParts {
        typ,
        alg: header.alg,
        kid: header.kid,
    })
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
