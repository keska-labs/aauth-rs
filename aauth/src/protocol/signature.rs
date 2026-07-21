//! `Signature-Key` header schemes and local key material.
//!
//! Wire schemes: `draft-hardt-httpbis-signature-key-05.txt` §3.
//! AAuth agent presentation typically uses `scheme=jwt` (`#keying-material`).

use std::convert::TryFrom;

use httpsig_key::protocol::{
    SignatureKey as HttpsigSignatureKey, SignatureKeyJwt as HttpsigSignatureKeyJwt, SigningMaterial,
};

use super::jwt::SigningJwk;
use crate::error::SignatureError;

/// `Signature-Key` header value using `scheme=jwt`.
///
/// Direction: Agent -> Resource/PS any signed request; Resource -> PS/AS when acting as agent.
///
/// Spec: `draft-hardt-httpbis-signature-key-05.txt` §3.6;
/// `draft-hardt-oauth-aauth-protocol.md#keying-material`
#[derive(Debug, Clone)]
pub struct SignatureKeyJwt {
    pub jwt: String,
}

/// `Signature-Key` header value using `scheme=jkt-jwt` (agent provider key-refresh only).
///
/// Direction: Agent -> AP bootstrap ceremonies (companion spec).
///
/// Spec: `draft-hardt-httpbis-signature-key-05.txt` §3.5;
/// `draft-hardt-oauth-aauth-protocol.md#keying-material`
#[derive(Debug, Clone)]
pub struct SignatureKeyJktJwt {
    pub jwt: String,
}

/// `Signature-Key` header value using `scheme=hwk` (not used for AAuth agent signing).
///
/// Spec: `draft-hardt-httpbis-signature-key-05.txt` §3.3;
/// `draft-hardt-oauth-aauth-protocol.md#keying-material`
#[derive(Debug, Clone, Copy)]
pub struct SignatureKeyHwk;

/// Parsed `Signature-Key` header scheme.
///
/// Direction: Agent -> Resource/PS/AS signed requests; PS -> AS federation requests (`jwks_uri`).
///
/// Spec: `draft-hardt-httpbis-signature-key-05.txt` §3;
/// `draft-hardt-oauth-aauth-protocol.md#keying-material`
#[derive(Debug, Clone)]
pub enum SignatureKey {
    Jwt(SignatureKeyJwt),
    JktJwt(SignatureKeyJktJwt),
    Hwk(SignatureKeyHwk),
}

/// Local signing key material bound to a `Signature-Key` presentation.
///
/// Spec: `draft-hardt-httpbis-signature-key-05.txt` §3;
/// `draft-hardt-oauth-aauth-protocol.md#keying-material`
#[derive(Debug, Clone)]
pub struct KeyMaterial {
    pub signing_jwk: SigningJwk,
    pub signature_key: SignatureKey,
}

impl TryFrom<&KeyMaterial> for SigningMaterial {
    type Error = SignatureError;

    fn try_from(material: &KeyMaterial) -> Result<Self, Self::Error> {
        let jwt = match &material.signature_key {
            SignatureKey::Jwt(j) => j.jwt.clone(),
            SignatureKey::JktJwt(j) => j.jwt.clone(),
            SignatureKey::Hwk(_) => return Err(SignatureError::HwkUnsupported),
        };
        Ok(SigningMaterial {
            signing_jwk: material.signing_jwk.clone(),
            signature_key: HttpsigSignatureKey::Jwt(HttpsigSignatureKeyJwt { jwt }),
        })
    }
}
