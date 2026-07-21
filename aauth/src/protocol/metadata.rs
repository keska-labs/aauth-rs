//! Well-known metadata and JWKS documents.

use jsonwebtoken::jwk::JwkSet;
use serde::{Deserialize, Serialize};

use crate::error::MetadataError;

/// Person Server metadata (`GET /.well-known/aauth-person.json`).
///
/// Direction: Any -> PS GET `/.well-known/aauth-person.json`.
///
/// Spec: `draft-hardt-oauth-aauth-protocol.md#ps-metadata`
#[serde_with::apply(
    Option => #[serde(default, skip_serializing_if = "Option::is_none")],
)]
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct PersonServerMetadata {
    /// PS HTTPS URL. MUST match the fetch URL.
    pub issuer: Option<String>,
    /// URL where agents send token requests.
    pub token_endpoint: String,
    /// URL to the PS JSON Web Key Set.
    pub jwks_uri: Option<String>,
    pub name: Option<String>,
    pub description: Option<String>,
    pub logo_uri: Option<String>,
    pub logo_dark_uri: Option<String>,
    pub documentation_uri: Option<String>,
    pub tos_uri: Option<String>,
    pub policy_uri: Option<String>,
    pub mission_endpoint: Option<String>,
    pub permission_endpoint: Option<String>,
    pub audit_endpoint: Option<String>,
    pub interaction_endpoint: Option<String>,
    pub mission_control_endpoint: Option<String>,
    pub revocation_endpoint: Option<String>,
    pub scopes_supported: Option<Vec<String>>,
    pub claims_supported: Option<Vec<String>>,
}

impl PersonServerMetadata {
    pub fn validate(&self) -> Result<(), MetadataError> {
        if self.token_endpoint.is_empty() {
            return Err(MetadataError::MissingTokenEndpoint);
        }
        Ok(())
    }
}

/// Access Server metadata (`GET /.well-known/aauth-access.json`).
///
/// Direction: PS/Agent/Resource -> AS GET `/.well-known/aauth-access.json`.
///
/// Spec: `draft-hardt-oauth-aauth-protocol.md#access-server-metadata`
#[serde_with::apply(
    Option => #[serde(default, skip_serializing_if = "Option::is_none")],
)]
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct AccessServerMetadata {
    pub issuer: Option<String>,
    pub token_endpoint: String,
    pub jwks_uri: Option<String>,
    pub name: Option<String>,
    pub description: Option<String>,
    pub logo_uri: Option<String>,
    pub logo_dark_uri: Option<String>,
    pub documentation_uri: Option<String>,
    pub tos_uri: Option<String>,
    pub policy_uri: Option<String>,
    pub revocation_endpoint: Option<String>,
}

impl AccessServerMetadata {
    pub fn validate(&self) -> Result<(), MetadataError> {
        if self.token_endpoint.is_empty() {
            return Err(MetadataError::MissingTokenEndpoint);
        }
        Ok(())
    }
}

/// Resource access mode advertised in resource metadata.
///
/// Spec: `draft-hardt-oauth-aauth-protocol.md#resource-metadata`
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum ResourceAccessModeWire {
    AgentToken,
    AauthAccessToken,
    AuthToken,
}

/// Resource metadata (`GET /.well-known/aauth-resource.json`).
///
/// Direction: Agent/PS/AS -> Resource GET `/.well-known/aauth-resource.json`.
///
/// Spec: `draft-hardt-oauth-aauth-protocol.md#resource-metadata`
#[serde_with::apply(
    Option => #[serde(default, skip_serializing_if = "Option::is_none")],
)]
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ResourceServerMetadata {
    pub issuer: Option<String>,
    pub jwks_uri: Option<String>,
    pub access_mode: Option<ResourceAccessModeWire>,
    pub name: Option<String>,
    pub description: Option<String>,
    pub logo_uri: Option<String>,
    pub logo_dark_uri: Option<String>,
    pub documentation_uri: Option<String>,
    pub tos_uri: Option<String>,
    pub policy_uri: Option<String>,
    pub authorization_endpoint: Option<String>,
    pub login_endpoint: Option<String>,
    pub scope_descriptions: Option<std::collections::HashMap<String, String>>,
    pub signature_window: Option<u64>,
    pub additional_signature_components: Option<Vec<String>>,
    pub revocation_endpoint: Option<String>,
    pub r3_vocabularies: Option<Vec<String>>,
}

/// Agent Provider metadata (`GET /.well-known/aauth-agent.json`).
///
/// Direction: Any -> AP GET `/.well-known/aauth-agent.json`.
///
/// Spec: `draft-hardt-oauth-aauth-protocol.md#agent-provider-metadata`
#[serde_with::apply(
    Option => #[serde(default, skip_serializing_if = "Option::is_none")],
)]
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AgentProviderMetadata {
    pub issuer: Option<String>,
    pub jwks_uri: String,
    pub name: Option<String>,
    pub description: Option<String>,
    pub logo_uri: Option<String>,
    pub logo_dark_uri: Option<String>,
    pub documentation_uri: Option<String>,
    pub callback_endpoint: Option<String>,
    pub event_endpoint: Option<String>,
    pub login_endpoint: Option<String>,
    pub localhost_callback_allowed: Option<bool>,
    pub tos_uri: Option<String>,
    pub policy_uri: Option<String>,
}

impl AgentProviderMetadata {
    /// Minimal metadata reconstructed from a cached JWKS URI.
    pub fn from_jwks_uri(jwks_uri: impl Into<String>) -> Self {
        Self {
            issuer: None,
            jwks_uri: jwks_uri.into(),
            name: None,
            description: None,
            logo_uri: None,
            logo_dark_uri: None,
            documentation_uri: None,
            callback_endpoint: None,
            event_endpoint: None,
            login_endpoint: None,
            localhost_callback_allowed: None,
            tos_uri: None,
            policy_uri: None,
        }
    }
}

///
/// Direction: Any -> issuer GET `{jwks_uri}`.
///
/// Spec: `draft-hardt-oauth-aauth-protocol.md#jwks-discovery-and-caching-jwks-discovery`
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct JwksDocument {
    #[serde(flatten)]
    pub keys: JwkSet,
}

/// Token revocation request body (`POST {revocation_endpoint}`).
///
/// Direction: PS -> Resource POST `{revocation_endpoint}`; AS -> Resource POST `{revocation_endpoint}`;
/// authorized party -> PS/AS POST `{revocation_endpoint}`.
///
/// Spec: `draft-hardt-oauth-aauth-protocol.md#token-revocation`
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RevocationRequest {
    pub jti: String,
}

#[cfg(test)]
mod tests {
    use super::{AccessServerMetadata, PersonServerMetadata, ResourceServerMetadata};

    #[test]
    fn person_metadata_deserializes() {
        let json = r#"{
            "issuer": "https://person.example",
            "token_endpoint": "https://person.example/token",
            "jwks_uri": "https://person.example/jwks"
        }"#;
        let meta: PersonServerMetadata = serde_json::from_str(json).expect("deserialize");
        assert!(meta.validate().is_ok());
    }

    #[test]
    fn access_metadata_deserializes() {
        let json = r#"{
            "issuer": "https://as.example",
            "token_endpoint": "https://as.example/token",
            "jwks_uri": "https://as.example/jwks"
        }"#;
        let meta: AccessServerMetadata = serde_json::from_str(json).expect("deserialize");
        assert!(meta.validate().is_ok());
    }

    #[test]
    fn resource_metadata_deserializes() {
        let json = r#"{
            "issuer": "https://resource.example",
            "authorization_endpoint": "https://resource.example/authorize"
        }"#;
        let meta: ResourceServerMetadata = serde_json::from_str(json).expect("deserialize");
        assert_eq!(
            meta.authorization_endpoint.as_deref(),
            Some("https://resource.example/authorize")
        );
    }
}
