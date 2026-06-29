use std::str::FromStr;

use jsonwebtoken::jwk::JwkSet;
use serde::{Deserialize, Serialize};
use serde_json::Value;

use crate::jwt::OkpSigningJwk;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ParseStrError;

/// AAuth JWT `typ` header values (`aa-*+jwt`).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum JwtTyp {
    Agent,
    Auth,
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

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum RequirementLevel {
    AgentToken,
    AuthToken,
    Approval,
    Interaction,
    Clarification,
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

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum Capability {
    Interaction,
    Clarification,
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

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AAuthChallenge {
    pub requirement: RequirementLevel,
    pub resource_token: Option<String>,
    pub url: Option<String>,
    pub code: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Mission {
    pub approver: String,
    pub s256: String,
}

/// Person Server metadata (`/.well-known/aauth-person.json`).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PersonServerMetadata {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub issuer: Option<String>,
    pub token_endpoint: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub jwks_uri: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub name: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub permission_endpoint: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub interaction_endpoint: Option<String>,
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
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AccessServerMetadata {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub issuer: Option<String>,
    pub token_endpoint: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub jwks_uri: Option<String>,
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
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ResourceServerMetadata {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub issuer: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub jwks_uri: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub authorization_endpoint: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub name: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct JwksDocument {
    #[serde(flatten)]
    pub keys: JwkSet,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MetadataDocument {
    pub jwks_uri: String,
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

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TokenExchangeRequest {
    pub resource_token: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub justification: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub localhost_callback: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub login_hint: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub tenant: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub domain_hint: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub capabilities: Option<Vec<String>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub prompt: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ClarificationChallenge {
    pub clarification: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ClarificationResponse {
    pub clarification_response: String,
}

#[derive(Debug, Clone)]
pub struct SignatureKeyJwt {
    pub jwt: String,
}

#[derive(Debug, Clone)]
pub struct SignatureKeyJktJwt {
    pub jwt: String,
}

#[derive(Debug, Clone, Copy)]
pub struct SignatureKeyHwk;

#[derive(Debug, Clone)]
pub enum SignatureKey {
    Jwt(SignatureKeyJwt),
    JktJwt(SignatureKeyJktJwt),
    Hwk(SignatureKeyHwk),
}

#[derive(Debug, Clone)]
pub struct KeyMaterial {
    pub signing_jwk: OkpSigningJwk,
    pub signature_key: SignatureKey,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AAuthProtocolError {
    pub error: String,
    #[serde(default)]
    pub error_description: Option<String>,
    #[serde(default)]
    pub error_uri: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TokenResponseBody {
    pub auth_token: String,
    pub expires_in: u64,
}
