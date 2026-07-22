use serde::{Deserialize, Serialize};
use serde_json::Value;

/// Key backend identifiers (config / resolve).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum KeyBackend {
    Software,
    #[serde(rename = "yubikey-piv")]
    YubikeyPiv,
    #[serde(rename = "secure-enclave")]
    SecureEnclave,
}

impl KeyBackend {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Software => "software",
            Self::YubikeyPiv => "yubikey-piv",
            Self::SecureEnclave => "secure-enclave",
        }
    }

    pub fn is_hardware(self) -> bool {
        !matches!(self, Self::Software)
    }

    pub fn parse(s: &str) -> Option<Self> {
        match s {
            "software" => Some(Self::Software),
            "yubikey-piv" => Some(Self::YubikeyPiv),
            "secure-enclave" => Some(Self::SecureEnclave),
            _ => None,
        }
    }
}

/// Signing algorithms used for agent JWTs.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum KeyAlgorithm {
    EdDSA,
    ES256,
    RS256,
}

impl KeyAlgorithm {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::EdDSA => "EdDSA",
            Self::ES256 => "ES256",
            Self::RS256 => "RS256",
        }
    }

    pub fn parse(s: &str) -> Option<Self> {
        match s {
            "EdDSA" => Some(Self::EdDSA),
            "ES256" => Some(Self::ES256),
            "RS256" => Some(Self::RS256),
            _ => None,
        }
    }
}

/// Metadata for a key registered in `~/.aauth/config.json`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct LocalKeyMeta {
    pub backend: KeyBackend,
    pub algorithm: KeyAlgorithm,
    /// Backend-specific ID: slot for PIV, label for SE, kid for software.
    pub key_id: String,
    pub device_label: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct AgentHosting {
    pub platform: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub repo: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct AgentConfig {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub agent_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub person_server_url: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub agent_server_url: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub jwks_uri: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub hosting: Option<AgentHosting>,
    #[serde(default)]
    pub keys: std::collections::BTreeMap<String, LocalKeyMeta>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Default)]
pub struct AAuthConfig {
    #[serde(default)]
    pub agents: std::collections::BTreeMap<String, AgentConfig>,
}

/// Software keys in the OS keychain (`service = "aauth"`).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct KeychainData {
    pub current: String,
    pub keys: std::collections::BTreeMap<String, Value>,
}

/// Resolved signing key.
#[derive(Debug, Clone)]
pub struct ResolvedKey {
    pub backend: KeyBackend,
    pub key_id: String,
    pub kid: String,
    pub algorithm: KeyAlgorithm,
    pub public_jwk: Value,
}

#[derive(Debug, Clone)]
pub struct SignatureKeyJwt {
    pub jwt: String,
}

impl SignatureKeyJwt {
    pub fn new(jwt: impl Into<String>) -> Self {
        Self { jwt: jwt.into() }
    }
}

#[derive(Debug, Clone)]
pub struct AgentTokenResult {
    /// Ephemeral private JWK for HTTP Message Signatures.
    pub signing_key: Value,
    pub signature_key: SignatureKeyJwt,
}

#[derive(Debug, Clone, Default)]
pub struct SignAgentTokenOptions {
    pub agent_url: String,
    pub sub: String,
    pub lifetime: Option<u64>,
    pub person_server_url: Option<String>,
}
