//! `Signature-Key` header schemes and local key material.

use super::jwt::OkpSigningJwk;

/// `Signature-Key` header value using `scheme=jwt`.
///
/// Direction: Agent -> Resource/PS any signed request; Resource -> PS/AS when acting as agent.
///
/// Spec: `draft-hardt-oauth-aauth-protocol.md#keying-material`
#[derive(Debug, Clone)]
pub struct SignatureKeyJwt {
    pub jwt: String,
}

/// `Signature-Key` header value using `scheme=jkt-jwt` (agent provider key-refresh only).
///
/// Direction: Agent -> AP bootstrap ceremonies (companion spec).
///
/// Spec: `draft-hardt-oauth-aauth-protocol.md#keying-material`
#[derive(Debug, Clone)]
pub struct SignatureKeyJktJwt {
    pub jwt: String,
}

/// `Signature-Key` header value using `scheme=hwk`.
///
/// Spec: `draft-hardt-oauth-aauth-protocol.md#keying-material`
#[derive(Debug, Clone, Copy)]
pub struct SignatureKeyHwk;

/// Parsed `Signature-Key` header scheme.
///
/// Direction: Agent -> Resource/PS/AS signed requests; PS -> AS federation requests (`jwks_uri`).
///
/// Spec: `draft-hardt-oauth-aauth-protocol.md#keying-material`
#[derive(Debug, Clone)]
pub enum SignatureKey {
    Jwt(SignatureKeyJwt),
    JktJwt(SignatureKeyJktJwt),
    Hwk(SignatureKeyHwk),
}

/// Local signing key material bound to a `Signature-Key` presentation.
///
/// Spec: `draft-hardt-oauth-aauth-protocol.md#keying-material`
#[derive(Debug, Clone)]
pub struct KeyMaterial {
    pub signing_jwk: OkpSigningJwk,
    pub signature_key: SignatureKey,
}
