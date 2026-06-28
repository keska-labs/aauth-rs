use serde::{Deserialize, Serialize};
use serde_json::Value;

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

    pub fn parse(value: &str) -> Option<Self> {
        match value {
            "aa-agent+jwt" => Some(Self::Agent),
            "aa-auth+jwt" => Some(Self::Auth),
            "aa-resource+jwt" => Some(Self::Resource),
            _ => None,
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

#[cfg(test)]
mod jwt_typ_tests {
    use super::JwtTyp;

    #[test]
    fn parse_and_display() {
        assert_eq!(JwtTyp::parse("aa-agent+jwt"), Some(JwtTyp::Agent));
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

    pub fn parse(value: &str) -> Option<Self> {
        match value {
            "agent-token" => Some(Self::AgentToken),
            "auth-token" => Some(Self::AuthToken),
            "approval" => Some(Self::Approval),
            "interaction" => Some(Self::Interaction),
            "clarification" => Some(Self::Clarification),
            "claims" => Some(Self::Claims),
            _ => None,
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

    pub fn parse(value: &str) -> Option<Self> {
        match value {
            "interaction" => Some(Self::Interaction),
            "clarification" => Some(Self::Clarification),
            "payment" => Some(Self::Payment),
            _ => None,
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

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VerifiedAgentToken {
    pub iss: String,
    pub dwk: String,
    pub sub: String,
    pub cnf_jwk: Value,
    pub iat: i64,
    pub exp: i64,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VerifiedAuthToken {
    pub iss: String,
    pub dwk: String,
    pub aud: Value,
    pub agent: String,
    pub cnf_jwk: Value,
    pub sub: Option<String>,
    pub scope: Option<String>,
    pub tenant: Option<String>,
    pub iat: i64,
    pub exp: i64,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum VerifiedToken {
    Agent(VerifiedAgentToken),
    Auth(VerifiedAuthToken),
}

impl VerifiedToken {
    pub fn token_type(&self) -> &'static str {
        match self {
            Self::Agent(_) => "agent",
            Self::Auth(_) => "auth",
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuthServerMetadata {
    pub token_endpoint: String,
    #[serde(default)]
    pub jwks_uri: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct JwksDocument {
    pub keys: Vec<Value>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MetadataDocument {
    pub jwks_uri: String,
    #[serde(flatten)]
    pub extra: std::collections::HashMap<String, Value>,
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
    pub signing_jwk: Value,
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
