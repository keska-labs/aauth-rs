use jsonwebtoken::{Algorithm, DecodingKey, TokenData, Validation, decode};
use serde::de::DeserializeOwned;

use crate::error::{JwtError, Result};

const CLOCK_SKEW: u64 = 60;

pub fn decode_unverified<T: DeserializeOwned>(jwt: &str) -> Result<TokenData<T>> {
    decode(
        jwt,
        &DecodingKey::from_secret(b"unused"),
        &unverified_validation(),
    )
    .map_err(|e| JwtError::Decode(e.to_string()).into())
}

pub fn decode_verified<T: DeserializeOwned>(
    jwt: &str,
    key: &DecodingKey,
    validation: &Validation,
) -> Result<TokenData<T>> {
    decode(jwt, key, validation).map_err(|e| JwtError::Decode(e.to_string()).into())
}

pub fn unverified_validation() -> Validation {
    let mut validation = Validation::new(Algorithm::EdDSA);
    validation.insecure_disable_signature_validation();
    validation.validate_aud = false;
    validation.validate_exp = false;
    validation
}

pub fn verified_validation() -> Validation {
    let mut validation = Validation::new(Algorithm::EdDSA);
    validation.validate_aud = false;
    validation.leeway = CLOCK_SKEW;
    validation
}
