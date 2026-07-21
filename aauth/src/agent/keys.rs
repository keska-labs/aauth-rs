use std::sync::Arc;

use jsonwebtoken::{Algorithm, Header, encode};
use uuid::Uuid;

use crate::error::Result;
use crate::jwt::{AgentClaims, CnfClaim};
use crate::keys::TestKeys;
use crate::protocol::{JwtTyp, KeyMaterial, SignatureKey, SignatureKeyJwt};

#[trait_variant::make(KeyMaterialProvider: Send)]
#[dynosaur::dynosaur(pub DynKeyMaterialProvider = dyn(box) KeyMaterialProvider, bridge(dyn))]
pub trait LocalKeyMaterialProvider: Sync {
    async fn key_material(&self) -> Result<KeyMaterial>;
}

impl<T: KeyMaterialProvider + Sync> KeyMaterialProvider for Arc<T> {
    async fn key_material(&self) -> Result<KeyMaterial> {
        (**self).key_material().await
    }
}

pub trait AgentJwtMinter: Send + Sync {
    fn mint_agent_jwt(&self, agent_url: &str, sub: &str, ps: Option<&str>) -> String;
}

#[derive(Clone)]
pub struct TestAgentJwtMinter {
    keys: TestKeys,
}

impl TestAgentJwtMinter {
    pub fn new(keys: TestKeys) -> Self {
        Self { keys }
    }
}

impl AgentJwtMinter for TestAgentJwtMinter {
    fn mint_agent_jwt(&self, agent_url: &str, sub: &str, ps: Option<&str>) -> String {
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs() as i64;

        let claims = AgentClaims {
            iss: agent_url.into(),
            dwk: "aauth-agent.json".into(),
            sub: sub.into(),
            jti: Uuid::new_v4().to_string(),
            cnf: CnfClaim {
                jwk: self.keys.agent_ephemeral.public_jwk(),
            },
            iat: now,
            exp: now + 3600,
            ps: ps.map(str::to_string),
            parent_agent: None,
        };

        let mut header = Header::new(Algorithm::EdDSA);
        header.typ = Some(JwtTyp::Agent.as_str().into());
        header.kid = self.keys.agent_root.kid().map(str::to_string);

        encode(&header, &claims, &self.keys.agent_root.encoding_key()).expect("sign agent jwt")
    }
}

impl TestKeys {
    pub fn agent_jwt_minter(&self) -> TestAgentJwtMinter {
        TestAgentJwtMinter::new(self.clone())
    }

    pub fn mint_agent_jwt(&self, agent_url: &str, sub: &str, ps: Option<&str>) -> String {
        AgentJwtMinter::mint_agent_jwt(&self.agent_jwt_minter(), agent_url, sub, ps)
    }

    pub fn key_provider(
        &self,
        agent_jwt: impl Into<String>,
    ) -> Arc<StaticKeyMaterialProvider> {
        Arc::new(StaticKeyMaterialProvider::from_test_keys(self, agent_jwt))
    }
}

pub struct StaticKeyMaterialProvider {
    material: KeyMaterial,
}

impl StaticKeyMaterialProvider {
    pub fn new(material: KeyMaterial) -> Self {
        Self { material }
    }

    pub fn from_test_keys(keys: &TestKeys, agent_jwt: impl Into<String>) -> Self {
        Self::new(KeyMaterial {
            signing_jwk: keys.agent_ephemeral.signing_jwk(),
            signature_key: SignatureKey::Jwt(SignatureKeyJwt {
                jwt: agent_jwt.into(),
            }),
        })
    }

    pub fn into_arc(self) -> Arc<Self> {
        Arc::new(self)
    }
}

impl KeyMaterialProvider for StaticKeyMaterialProvider {
    async fn key_material(&self) -> Result<KeyMaterial> {
        Ok(self.material.clone())
    }
}
