//! `Signature-Key` header schemes and local key material.
//!
//! Wire schemes: `draft-hardt-httpbis-signature-key-05.txt` §3.
//! AAuth agent presentation typically uses `scheme=jwt` (`#keying-material`).

use super::jwt::SigningJwk;

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
