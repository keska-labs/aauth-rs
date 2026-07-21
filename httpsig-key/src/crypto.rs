//! JWK ↔ [`httpsig`] key material.

use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use httpsig::prelude::{AlgorithmName, PublicKey, SecretKey};

use crate::error::{Error, Result};
use crate::protocol::{PublicJwk, SigningJwk};

pub fn secret_key_from_signing_jwk(jwk: &SigningJwk) -> Result<SecretKey> {
    let d = URL_SAFE_NO_PAD
        .decode(&jwk.d)
        .map_err(Error::InvalidEncoding)?;
    match (jwk.kty.as_str(), jwk.crv.as_str()) {
        ("OKP", "Ed25519") => {
            if d.len() != 32 {
                return Err(Error::InvalidKeyLength);
            }
            Ok(SecretKey::from_bytes(&AlgorithmName::Ed25519, &d)?)
        }
        ("EC", "P-256") => {
            if d.len() != 32 {
                return Err(Error::InvalidKeyLength);
            }
            Ok(SecretKey::from_bytes(&AlgorithmName::EcdsaP256Sha256, &d)?)
        }
        _ => Err(Error::UnsupportedSigningJwk {
            kty: jwk.kty.clone(),
            crv: jwk.crv.clone(),
        }),
    }
}

pub fn public_key_from_jwk(jwk: &PublicJwk) -> Result<PublicKey> {
    match (jwk.kty.as_str(), jwk.crv.as_str()) {
        ("OKP", "Ed25519") => {
            let x = URL_SAFE_NO_PAD
                .decode(&jwk.x)
                .map_err(Error::InvalidEncoding)?;
            if x.len() != 32 {
                return Err(Error::InvalidKeyLength);
            }
            Ok(PublicKey::from_bytes(&AlgorithmName::Ed25519, &x)?)
        }
        ("EC", "P-256") => {
            let y = jwk.y.as_deref().ok_or(Error::MissingEcY)?;
            let x = URL_SAFE_NO_PAD
                .decode(&jwk.x)
                .map_err(Error::InvalidEncoding)?;
            let y = URL_SAFE_NO_PAD.decode(y).map_err(Error::InvalidEncoding)?;
            if x.len() != 32 || y.len() != 32 {
                return Err(Error::InvalidKeyLength);
            }
            let mut sec1 = Vec::with_capacity(65);
            sec1.push(0x04);
            sec1.extend_from_slice(&x);
            sec1.extend_from_slice(&y);
            Ok(PublicKey::from_bytes(
                &AlgorithmName::EcdsaP256Sha256,
                &sec1,
            )?)
        }
        _ => Err(Error::UnsupportedSigningJwk {
            kty: jwk.kty.clone(),
            crv: jwk.crv.clone(),
        }),
    }
}
