use jsonwebtoken::{
    Algorithm, DecodingKey, TokenData, Validation, dangerous::insecure_decode, decode,
    decode_header,
};
use serde::de::DeserializeOwned;

use crate::error::{JwtError, Result};

const CLOCK_SKEW: u64 = 60;

pub fn decode_unverified<T: DeserializeOwned>(jwt: &str) -> Result<TokenData<T>> {
    insecure_decode(jwt)
        .map_err(JwtError::Decode)
        .map_err(Into::into)
}

pub fn decode_verified<T: DeserializeOwned>(
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
    let header = decode_header(jwt).map_err(JwtError::Decode)?;
    Ok(verified_validation(header.alg))
}
