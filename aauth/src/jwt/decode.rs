use jsonwebtoken::{
    Algorithm, DecodingKey, TokenData, Validation, dangerous::insecure_decode, decode,
};
use serde::de::DeserializeOwned;

use crate::error::{JwtError, Result};

const CLOCK_SKEW: u64 = 60;

pub fn decode_unverified<T: DeserializeOwned>(jwt: &str) -> Result<TokenData<T>> {
    insecure_decode(jwt).map_err(|e| JwtError::Decode(e.to_string()).into())
}

pub fn decode_verified<T: DeserializeOwned>(
    jwt: &str,
    key: &DecodingKey,
    validation: &Validation,
) -> Result<TokenData<T>> {
    decode(jwt, key, validation).map_err(|e| JwtError::Decode(e.to_string()).into())
}

pub fn verified_validation() -> Validation {
    let mut validation = Validation::new(Algorithm::EdDSA);
    validation.validate_aud = false;
    validation.leeway = CLOCK_SKEW;
    validation
}
