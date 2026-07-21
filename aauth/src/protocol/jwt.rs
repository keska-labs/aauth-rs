//! JWT token payload structures and `typ` header values.

use std::str::FromStr;

use serde::{Deserialize, Serialize};

use super::common::{Mission, ParseStrError};

/// AAuth JWT `typ` header values.
///
/// Direction: carried in agent/auth/resource JWT headers on any signed request.
///
/// Spec: `draft-hardt-oauth-aauth-protocol.md#jwt-type-registrations`
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum JwtTyp {
    /// `aa-agent+jwt` — agent token.
    Agent,
    /// `aa-auth+jwt` — auth token.
    Auth,
    /// `aa-resource+jwt` — resource token.
    Resource,
}

impl JwtTyp {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Agent => "aa-agent+jwt",
            Self::Auth => "aa-auth+jwt",
            Self::Resource => "aa-resource+jwt",
        }
    }

    pub fn verify_error_code(self) -> &'static str {
        match self {
            Self::Agent => "invalid_agent_token",
            Self::Auth => "invalid_auth_token",
            Self::Resource => "invalid_resource_token",
        }
    }
}

impl std::fmt::Display for JwtTyp {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.as_str())
    }
}

impl FromStr for JwtTyp {
    type Err = ParseStrError;

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        match value {
            "aa-agent+jwt" => Ok(Self::Agent),
            "aa-auth+jwt" => Ok(Self::Auth),
            "aa-resource+jwt" => Ok(Self::Resource),
            _ => Err(ParseStrError),
        }
    }
}

/// Public JWK used in JWKS and JWT `cnf.jwk` claims (`OKP`/Ed25519 or `EC`/P-256).
///
/// Re-exported from [`httpsig_key`] so HTTP Signature Keys and AAuth JWTs share one type.
///
/// Direction: Any -> Any GET `{jwks_uri}`; embedded in JWT `cnf.jwk` claims.
///
/// Spec: `draft-hardt-oauth-aauth-protocol.md#jwks-discovery-and-caching-jwks-discovery`
pub use httpsig_key::PublicJwk;

/// Private signing JWK (`OKP`/Ed25519 or `EC`/P-256).
///
/// Re-exported from [`httpsig_key`].
///
/// Direction: local signing material; public half published via GET `{jwks_uri}`.
///
/// Spec: `draft-hardt-oauth-aauth-protocol.md#keying-material`
pub use httpsig_key::SigningJwk;

/// RFC 7800 confirmation claim binding a token to a public key.
///
/// Direction: embedded in agent and auth JWT payloads presented via `Signature-Key`.
///
/// Spec: `draft-hardt-oauth-aauth-protocol.md#agent-token-structure`
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CnfClaim {
    /// Agent public key. MUST match the key used to sign the HTTP request.
    pub jwk: PublicJwk,
}

/// RFC 8693-style delegation chain node in an auth token.
///
/// Direction: embedded in auth JWT payload (PS -> Agent or AS -> PS -> Agent).
///
/// Spec: `draft-hardt-oauth-aauth-protocol.md#delegation-chain`,
/// `#call-chaining`, `#upstream-token-verification`, `#sub-agents`
#[serde_with::apply(
    Option => #[serde(default, skip_serializing_if = "Option::is_none")],
)]
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ActClaim {
    /// `aauth:` URI of the immediate upstream agent.
    pub agent: String,
    /// Nested upstream delegation, when present.
    pub act: Option<Box<ActClaim>>,
}

/// Agent token JWT payload (`typ: aa-agent+jwt`).
///
/// Direction: AP -> Agent (bootstrap, out of scope); Agent -> Resource/PS any signed request
/// via `Signature-Key: sig=jwt`.
///
/// Spec: `draft-hardt-oauth-aauth-protocol.md#agent-token-agent-tokens`
#[serde_with::apply(
    Option => #[serde(default, skip_serializing_if = "Option::is_none")],
)]
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AgentClaims {
    /// Agent provider URL.
    pub iss: String,
    /// Well-known metadata document name for key discovery. MUST be `aauth-agent.json`.
    pub dwk: String,
    /// Agent identifier (`aauth:local@domain`), stable across key rotations.
    pub sub: String,
    /// Unique token identifier for replay detection, audit, and revocation.
    pub jti: String,
    /// Confirmation claim with the agent's public key.
    pub cnf: CnfClaim,
    /// Issued-at timestamp.
    pub iat: i64,
    /// Expiration timestamp.
    pub exp: i64,
    /// HTTPS URL of the agent's person server. Distinct from `iss`.
    pub ps: Option<String>,
    /// Parent agent identifier when this token belongs to a sub-agent.
    ///
    /// Spec: `draft-hardt-oauth-aauth-protocol.md#sub-agents`
    pub parent_agent: Option<String>,
}

impl AgentClaims {
    pub fn identifier(&self) -> &str {
        &self.sub
    }
}

/// Auth token JWT payload (`typ: aa-auth+jwt`).
///
/// Direction: PS -> Agent 200 `{token_endpoint}`; AS -> PS 200 `{token_endpoint}` (federated);
/// Agent -> Resource any signed request via `Signature-Key`.
///
/// Spec: `draft-hardt-oauth-aauth-protocol.md#auth-token-auth-tokens`
#[serde_with::apply(
    Option => #[serde(default, skip_serializing_if = "Option::is_none")],
)]
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AuthClaims {
    /// URL of the server that issued the auth token (AS or PS).
    pub iss: String,
    /// Well-known metadata document name for key discovery.
    pub dwk: String,
    /// URL of the resource the agent is authorized to access.
    pub aud: String,
    /// Unique token identifier for replay detection, audit, and revocation.
    pub jti: String,
    /// Agent identifier authorized to use this token.
    pub agent: String,
    /// Upstream delegation chain. Absent when the agent obtained the token directly.
    pub act: Option<ActClaim>,
    /// Confirmation claim with the agent's public key.
    pub cnf: CnfClaim,
    /// Issued-at timestamp.
    pub iat: i64,
    /// Expiration timestamp.
    pub exp: i64,
    /// Directed user identifier.
    pub sub: Option<String>,
    /// Authorized scopes as a space-separated string.
    pub scope: Option<String>,
    /// Tenant identifier per OpenID Connect Enterprise Extensions.
    pub tenant: Option<String>,
    /// Mission reference when the auth token was issued in mission context.
    pub mission: Option<Mission>,
}

/// Resource-initiated interaction embedded in a resource token.
///
/// Direction: Resource -> PS embedded in resource JWT; PS -> User browser redirect to `{url}`.
///
/// Spec: `draft-hardt-oauth-aauth-protocol.md#resource-token-structure`
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ResourceInteractionClaim {
    /// HTTPS URL of the resource's interaction endpoint.
    pub url: String,
    /// Interaction code to present at that URL.
    pub code: String,
}

/// Resource token JWT payload (`typ: aa-resource+jwt`).
///
/// Direction: Resource -> Agent 200 `{authorization_endpoint}` or 401/402 `AAuth-Requirement`;
/// Agent -> PS POST `{token_endpoint}` body `resource_token`; PS -> AS POST `{token_endpoint}` body
/// `resource_token`.
///
/// Spec: `draft-hardt-oauth-aauth-protocol.md#resource-token-structure`
#[serde_with::apply(
    Option => #[serde(default, skip_serializing_if = "Option::is_none")],
)]
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ResourceClaims {
    /// Resource URL.
    pub iss: String,
    /// Well-known metadata document name for key discovery. MUST be `aauth-resource.json`.
    pub dwk: String,
    /// Token audience: PS URL (three-party) or AS URL (four-party).
    pub aud: String,
    /// Unique token identifier for replay detection, audit, and revocation.
    pub jti: String,
    /// Agent identifier the token is issued for.
    pub agent: String,
    /// JWK Thumbprint of the agent's current signing key.
    pub agent_jkt: String,
    /// Issued-at timestamp.
    pub iat: u64,
    /// Expiration timestamp.
    pub exp: u64,
    /// Requested scopes as a space-separated string.
    pub scope: Option<String>,
    /// Mission reference when the resource is mission-aware.
    pub mission: Option<Mission>,
    /// Present when the resource requires its own user-facing flow before authorization.
    pub interaction: Option<ResourceInteractionClaim>,
}

#[cfg(test)]
mod tests {
    use super::JwtTyp;
    use std::str::FromStr;

    #[test]
    fn parse_and_display() {
        assert_eq!(JwtTyp::from_str("aa-agent+jwt"), Ok(JwtTyp::Agent));
        assert_eq!(JwtTyp::Auth.as_str(), "aa-auth+jwt");
        assert_eq!(JwtTyp::Resource.to_string(), "aa-resource+jwt");
    }
}
