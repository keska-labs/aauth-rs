use std::str::FromStr;

use jsonwebtoken::jwk::JwkSet;
use serde::{Deserialize, Serialize};
use serde_json::Value;

use crate::jwt::OkpSigningJwk;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ParseStrError;

/// AAuth JWT `typ` header values.
///
/// Spec: https://github.com/dickhardt/AAuth/blob/main/draft-hardt-oauth-aauth-protocol.md#jwt-type-registrations
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

#[cfg(test)]
mod jwt_typ_tests {
    use super::JwtTyp;
    use std::str::FromStr;

    #[test]
    fn parse_and_display() {
        assert_eq!(JwtTyp::from_str("aa-agent+jwt"), Ok(JwtTyp::Agent));
        assert_eq!(JwtTyp::Auth.as_str(), "aa-auth+jwt");
        assert_eq!(JwtTyp::Resource.to_string(), "aa-resource+jwt");
    }
}

/// `AAuth-Requirement` `requirement` member values.
///
/// Spec: https://github.com/dickhardt/AAuth/blob/main/draft-hardt-oauth-aauth-protocol.md#requirement-values
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum RequirementLevel {
    /// `401` — AAuth agent token required for identity-only access.
    AgentToken,
    /// `401` — auth token required; carries a `resource-token` parameter.
    AuthToken,
    /// `202` — approval pending; poll `Location` for result.
    Approval,
    /// `202` — user action required at an interaction endpoint.
    Interaction,
    /// `202` — question posed to the recipient.
    Clarification,
    /// `202` — identity claims required (AS only).
    Claims,
}

impl RequirementLevel {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::AgentToken => "agent-token",
            Self::AuthToken => "auth-token",
            Self::Approval => "approval",
            Self::Interaction => "interaction",
            Self::Clarification => "clarification",
            Self::Claims => "claims",
        }
    }
}

impl std::fmt::Display for RequirementLevel {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.as_str())
    }
}

impl FromStr for RequirementLevel {
    type Err = ParseStrError;

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        match value {
            "agent-token" => Ok(Self::AgentToken),
            "auth-token" => Ok(Self::AuthToken),
            "approval" => Ok(Self::Approval),
            "interaction" => Ok(Self::Interaction),
            "clarification" => Ok(Self::Clarification),
            "claims" => Ok(Self::Claims),
            _ => Err(ParseStrError),
        }
    }
}

/// `AAuth-Capabilities` header and token-request capability values.
///
/// Spec: https://github.com/dickhardt/AAuth/blob/main/draft-hardt-oauth-aauth-protocol.md#aauth-capabilities-request-header-aauth-capabilities
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum Capability {
    /// Agent can get a user to an interaction URL, directly or via its PS.
    Interaction,
    /// Agent can engage in clarification chat.
    Clarification,
    /// Agent can handle `402` payment flows.
    Payment,
}

impl Capability {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Interaction => "interaction",
            Self::Clarification => "clarification",
            Self::Payment => "payment",
        }
    }
}

impl std::fmt::Display for Capability {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.as_str())
    }
}

impl FromStr for Capability {
    type Err = ParseStrError;

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        match value {
            "interaction" => Ok(Self::Interaction),
            "clarification" => Ok(Self::Clarification),
            "payment" => Ok(Self::Payment),
            _ => Err(ParseStrError),
        }
    }
}

/// `202` pending response body `status` values.
///
/// Spec: https://github.com/dickhardt/AAuth/blob/main/draft-hardt-oauth-aauth-protocol.md#pending-response
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum PendingStatus {
    /// Request is waiting for completion.
    Pending,
    /// User has arrived at the interaction endpoint.
    Interacting,
}

/// Parsed `AAuth-Requirement` response header.
///
/// Spec: https://github.com/dickhardt/AAuth/blob/main/draft-hardt-oauth-aauth-protocol.md#aauth-requirement-header-structure
///
/// Each variant carries only the parameters defined for that requirement level.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AAuthChallenge {
    /// `401` — AAuth agent token required for identity-only access.
    AgentToken,
    /// `401` — auth token required.
    AuthToken {
        /// Resource token JWT from the `resource-token` parameter.
        resource_token: String,
    },
    /// `202` — approval pending; poll `Location` for result.
    Approval,
    /// `202` — user action required at an interaction endpoint.
    Interaction {
        /// Interaction URL. MUST use `https` with no query or fragment.
        url: String,
        /// Interaction code.
        code: String,
    },
    /// `202` — question posed to the recipient (details in response body).
    Clarification,
    /// `202` — identity claims required (details in response body).
    Claims,
}

impl AAuthChallenge {
    pub fn level(&self) -> RequirementLevel {
        match self {
            Self::AgentToken => RequirementLevel::AgentToken,
            Self::AuthToken { .. } => RequirementLevel::AuthToken,
            Self::Approval => RequirementLevel::Approval,
            Self::Interaction { .. } => RequirementLevel::Interaction,
            Self::Clarification => RequirementLevel::Clarification,
            Self::Claims => RequirementLevel::Claims,
        }
    }
}

/// Mission reference (`approver`, `s256`) in headers and JWT claims.
///
/// Spec: https://github.com/dickhardt/AAuth/blob/main/draft-hardt-oauth-aauth-protocol.md#aauth-mission-request-header
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Mission {
    /// HTTPS URL of the entity that approved the mission. Compared by exact string match.
    pub approver: String,
    /// Unpadded base64url SHA-256 digest of the approved mission JSON bytes.
    pub s256: String,
}

/// Person Server metadata (`/.well-known/aauth-person.json`).
///
/// Spec: https://github.com/dickhardt/AAuth/blob/main/draft-hardt-oauth-aauth-protocol.md#person-server-metadata-ps-metadata
///
/// When fetching, `issuer` MUST match the URL the document was retrieved from.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PersonServerMetadata {
    /// PS HTTPS URL. MUST match the fetch URL and is placed in JWT `iss` claims.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub issuer: Option<String>,
    /// URL where agents send token requests.
    pub token_endpoint: String,
    /// URL to the PS JSON Web Key Set.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub jwks_uri: Option<String>,
    /// Human-readable display name.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub name: Option<String>,
    /// URL where agents request permission for non-resource actions.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub permission_endpoint: Option<String>,
    /// URL where agents relay interactions to the user through the PS.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub interaction_endpoint: Option<String>,
    /// URL for mission lifecycle operations.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub mission_endpoint: Option<String>,
}

impl PersonServerMetadata {
    pub fn validate(&self) -> Result<(), String> {
        if self.token_endpoint.is_empty() {
            return Err("Person server metadata missing token_endpoint".into());
        }
        Ok(())
    }
}

#[cfg(test)]
mod metadata_tests {
    use super::{AccessServerMetadata, PersonServerMetadata, ResourceServerMetadata};

    #[test]
    fn person_metadata_deserializes_optional_fields() {
        let json = r#"{
            "issuer": "https://person.example",
            "token_endpoint": "https://person.example/aauth/token",
            "jwks_uri": "https://person.example/jwks",
            "name": "Example PS"
        }"#;
        let meta: PersonServerMetadata = serde_json::from_str(json).expect("deserialize");
        assert_eq!(meta.issuer.as_deref(), Some("https://person.example"));
        assert_eq!(meta.token_endpoint, "https://person.example/aauth/token");
        assert!(meta.validate().is_ok());
    }

    #[test]
    fn access_metadata_deserializes_optional_fields() {
        let json = r#"{
            "issuer": "https://as.example",
            "token_endpoint": "https://as.example/aauth/token",
            "jwks_uri": "https://as.example/jwks"
        }"#;
        let meta: AccessServerMetadata = serde_json::from_str(json).expect("deserialize");
        assert_eq!(meta.issuer.as_deref(), Some("https://as.example"));
        assert!(meta.validate().is_ok());
    }

    #[test]
    fn resource_metadata_deserializes_optional_fields() {
        let json = r#"{
            "issuer": "https://resource.example",
            "jwks_uri": "https://resource.example/jwks",
            "authorization_endpoint": "https://resource.example/authorize"
        }"#;
        let meta: ResourceServerMetadata = serde_json::from_str(json).expect("deserialize");
        assert_eq!(meta.issuer.as_deref(), Some("https://resource.example"));
        assert_eq!(
            meta.authorization_endpoint.as_deref(),
            Some("https://resource.example/authorize")
        );
    }
}

/// Access Server metadata (`/.well-known/aauth-access.json`).
///
/// Spec: https://github.com/dickhardt/AAuth/blob/main/draft-hardt-oauth-aauth-protocol.md#access-server-metadata
///
/// When fetching, `issuer` MUST match the URL the document was retrieved from.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AccessServerMetadata {
    /// AS HTTPS URL. MUST match the fetch URL and is placed in auth token `iss` claims.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub issuer: Option<String>,
    /// URL where PSes send token requests.
    pub token_endpoint: String,
    /// URL to the AS JSON Web Key Set.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub jwks_uri: Option<String>,
    /// Human-readable display name.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub name: Option<String>,
}

impl AccessServerMetadata {
    pub fn validate(&self) -> Result<(), String> {
        if self.token_endpoint.is_empty() {
            return Err("Access server metadata missing token_endpoint".into());
        }
        Ok(())
    }
}

/// Resource metadata (`/.well-known/aauth-resource.json`).
///
/// Spec: https://github.com/dickhardt/AAuth/blob/main/draft-hardt-oauth-aauth-protocol.md#resource-metadata
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ResourceServerMetadata {
    /// Resource HTTPS URL. Placed in resource token `iss` claims.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub issuer: Option<String>,
    /// URL to the resource JSON Web Key Set. REQUIRED when the resource issues resource tokens.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub jwks_uri: Option<String>,
    /// URL where agents proactively request authorization.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub authorization_endpoint: Option<String>,
    /// Human-readable display name.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub name: Option<String>,
}

/// JSON Web Key Set document.
///
/// Spec: https://github.com/dickhardt/AAuth/blob/main/draft-hardt-oauth-aauth-protocol.md#jwks-discovery-and-caching-jwks-discovery
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct JwksDocument {
    /// JWKS `keys` array.
    #[serde(flatten)]
    pub keys: JwkSet,
}

/// Agent provider metadata (`/.well-known/aauth-agent.json`), partially typed.
///
/// Spec: https://github.com/dickhardt/AAuth/blob/main/draft-hardt-oauth-aauth-protocol.md#agent-provider-metadata
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MetadataDocument {
    /// URL to the agent provider JSON Web Key Set.
    pub jwks_uri: String,
    /// Additional metadata fields (`issuer`, `callback_endpoint`, etc.).
    #[serde(flatten)]
    pub extra: std::collections::HashMap<String, Value>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AgentOkResponse {
    pub status: String,
    pub agent: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuthOkResponse {
    pub status: String,
    pub user: Option<String>,
}

/// PS-to-AS token exchange request body.
///
/// Spec: https://github.com/dickhardt/AAuth/blob/main/draft-hardt-oauth-aauth-protocol.md#ps-to-as-token-request
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AccessTokenExchangeRequest {
    /// Resource token issued by the resource.
    pub resource_token: String,
    /// Agent token. For sub-agent authorization, this is the parent agent's token.
    pub agent_token: String,
    /// Auth token from an upstream authorization, used in call chaining.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub upstream_token: Option<String>,
    /// Sub-agent agent token for parent-mediated sub-agent authorization.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub subagent_token: Option<String>,
}

/// `202` pending response body for `requirement=claims`.
///
/// Spec: https://github.com/dickhardt/AAuth/blob/main/draft-hardt-oauth-aauth-protocol.md#claims-required-requirement-claims
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ClaimsChallenge {
    /// `"pending"` while waiting for claims submission.
    pub status: PendingStatus,
    /// Claim names the recipient MUST provide (including directed `sub`).
    pub required_claims: Vec<String>,
}

/// Agent POST body to the PS `token_endpoint`.
///
/// Spec: https://github.com/dickhardt/AAuth/blob/main/draft-hardt-oauth-aauth-protocol.md#agent-token-request
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TokenExchangeRequest {
    /// Resource token.
    pub resource_token: String,
    /// Auth token from an upstream authorization, used in call chaining.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub upstream_token: Option<String>,
    /// Sub-agent agent token for parent-mediated sub-agent authorization.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub subagent_token: Option<String>,
    /// Markdown string declaring why access is being requested.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub justification: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub localhost_callback: Option<String>,
    /// Hint about who to authorize, per OpenID Connect Core Section 3.1.2.1.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub login_hint: Option<String>,
    /// Tenant identifier, per OpenID Connect Enterprise Extensions.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub tenant: Option<String>,
    /// Domain hint, per OpenID Connect Enterprise Extensions.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub domain_hint: Option<String>,
    /// Capability values the agent can handle for this request.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub capabilities: Option<Vec<Capability>>,
    /// Space-delimited prompt values (`none`, `login`, `consent`, `select_account`).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub prompt: Option<String>,
    /// Runtime platform identifier from the AAuth Platform Value Registry.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub platform: Option<String>,
    /// Short human-readable device label for display (max 64 UTF-8 printable characters).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub device: Option<String>,
}

/// `202` pending response body for `requirement=clarification`.
///
/// Spec: https://github.com/dickhardt/AAuth/blob/main/draft-hardt-oauth-aauth-protocol.md#clarification-required-requirement-clarification
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ClarificationChallenge {
    /// `"pending"` while waiting for a response.
    #[serde(default = "default_pending_status")]
    pub status: PendingStatus,
    /// Markdown question the recipient MUST answer.
    pub clarification: String,
    /// Seconds until the server times out the request.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub timeout: Option<u64>,
    /// Discrete answer choices, when applicable.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub options: Option<Vec<String>>,
}

fn default_pending_status() -> PendingStatus {
    PendingStatus::Pending
}

/// Agent POST body to answer a clarification on a pending URL.
///
/// Spec: https://github.com/dickhardt/AAuth/blob/main/draft-hardt-oauth-aauth-protocol.md#clarification-response
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ClarificationResponse {
    /// Markdown answer to the clarification question.
    pub clarification_response: String,
}

/// `Signature-Key` header value using `scheme=jwt`.
///
/// Spec: https://github.com/dickhardt/AAuth/blob/main/draft-hardt-oauth-aauth-protocol.md#keying-material
#[derive(Debug, Clone)]
pub struct SignatureKeyJwt {
    /// Agent or auth token JWT presented via `Signature-Key`.
    pub jwt: String,
}

/// `Signature-Key` header value using `scheme=jkt-jwt` (agent provider key-refresh only).
///
/// Spec: https://github.com/dickhardt/AAuth/blob/main/draft-hardt-oauth-aauth-protocol.md#keying-material
#[derive(Debug, Clone)]
pub struct SignatureKeyJktJwt {
    /// Delegation JWT for hardware-key refresh ceremonies.
    pub jwt: String,
}

/// `Signature-Key` header value using `scheme=hwk`. Not used for AAuth resource/PS/AS access.
///
/// Spec: https://github.com/dickhardt/AAuth/blob/main/draft-hardt-oauth-aauth-protocol.md#keying-material
#[derive(Debug, Clone, Copy)]
pub struct SignatureKeyHwk;

/// Parsed `Signature-Key` header scheme.
///
/// Spec: https://github.com/dickhardt/AAuth/blob/main/draft-hardt-oauth-aauth-protocol.md#keying-material
///
/// AAuth agents MUST use [`SignatureKey::Jwt`] for resource, PS, and AS requests.
#[derive(Debug, Clone)]
pub enum SignatureKey {
    /// `scheme=jwt` — agent or auth token.
    Jwt(SignatureKeyJwt),
    /// `scheme=jkt-jwt` — hardware-key delegation (bootstrap only).
    JktJwt(SignatureKeyJktJwt),
    /// `scheme=hwk` — bare inline public key (not used for AAuth access).
    Hwk(SignatureKeyHwk),
}

/// Local signing key material bound to a `Signature-Key` presentation.
///
/// Spec: https://github.com/dickhardt/AAuth/blob/main/draft-hardt-oauth-aauth-protocol.md#keying-material
#[derive(Debug, Clone)]
pub struct KeyMaterial {
    /// Private JWK used to sign HTTP requests.
    pub signing_jwk: OkpSigningJwk,
    /// Token or key reference conveyed in `Signature-Key`.
    pub signature_key: SignatureKey,
}

/// Token endpoint or polling error response body.
///
/// Spec: https://github.com/dickhardt/AAuth/blob/main/draft-hardt-oauth-aauth-protocol.md#token-endpoint-error-response-format-error-response-format
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AAuthProtocolError {
    /// Single error code (for example `invalid_request`, `denied`, `expired`).
    pub error: String,
    /// Human-readable description.
    #[serde(default)]
    pub error_description: Option<String>,
    #[serde(default)]
    pub error_uri: Option<String>,
}

/// Direct grant (`200`) token endpoint response.
///
/// Spec: https://github.com/dickhardt/AAuth/blob/main/draft-hardt-oauth-aauth-protocol.md#ps-response
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TokenResponseBody {
    /// Issued auth token JWT.
    pub auth_token: String,
    /// Auth token lifetime in seconds.
    pub expires_in: u64,
}
