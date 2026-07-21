//! Public and private JWKs used with Signature-Key schemes.
//!
//! Spec: `draft-hardt-httpbis-signature-key-05.txt` §3.3 (hwk), §3.6 (jwt `cnf.jwk`)

use serde::{Deserialize, Serialize};

/// Public JWK (`OKP`/Ed25519 or `EC`/P-256).
///
/// Spec: `draft-hardt-httpbis-signature-key-05.txt` §3.3, §3.6
#[serde_with::apply(
    Option => #[serde(default, skip_serializing_if = "Option::is_none")],
)]
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PublicJwk {
    pub kty: String,
    pub crv: String,
    pub x: String,
    /// Required for `kty=EC`.
    pub y: Option<String>,
    pub kid: Option<String>,
}

/// Private signing JWK (`OKP`/Ed25519 or `EC`/P-256).
#[serde_with::apply(
    Option => #[serde(default, skip_serializing_if = "Option::is_none")],
)]
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SigningJwk {
    pub kty: String,
    pub crv: String,
    pub x: String,
    pub y: Option<String>,
    pub d: String,
    pub kid: Option<String>,
}

impl SigningJwk {
    pub fn public_jwk(&self) -> PublicJwk {
        PublicJwk {
            kty: self.kty.clone(),
            crv: self.crv.clone(),
            x: self.x.clone(),
            y: self.y.clone(),
            kid: self.kid.clone(),
        }
    }
}
