use async_trait::async_trait;
use jsonwebtoken::{Algorithm, Header, encode};
use uuid::Uuid;

use crate::jwt::{ActClaim, AuthClaims, CnfClaim, ResourceClaims};
use crate::keys::{Ed25519KeyPair, TestKeys};
use crate::types::JwtTyp;

pub trait AuthJwtMinter: Send + Sync {
    fn mint_auth_jwt(
        &self,
        iss: &str,
        aud: &str,
        agent: &str,
        sub: Option<&str>,
        scope: Option<&str>,
    ) -> String;
}

#[derive(Clone)]
pub struct TestAuthJwtMinter {
    keys: TestKeys,
}

impl TestAuthJwtMinter {
    pub fn new(keys: TestKeys) -> Self {
        Self { keys }
    }
}

impl AuthJwtMinter for TestAuthJwtMinter {
    fn mint_auth_jwt(
        &self,
        iss: &str,
        aud: &str,
        agent: &str,
        sub: Option<&str>,
        scope: Option<&str>,
    ) -> String {
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs() as i64;

        let claims = AuthClaims {
            iss: iss.into(),
            dwk: "aauth-person.json".into(),
            aud: aud.into(),
            jti: Uuid::new_v4().to_string(),
            agent: agent.into(),
            act: ActClaim { sub: agent.into() },
            cnf: CnfClaim {
                jwk: self.keys.agent_ephemeral.public_jwk(),
            },
            iat: now,
            exp: now + 3600,
            sub: sub.map(str::to_string),
            scope: scope.map(str::to_string),
            tenant: None,
            mission: None,
        };

        let mut header = Header::new(Algorithm::EdDSA);
        header.typ = Some(JwtTyp::Auth.as_str().into());
        header.kid = self.keys.auth_server.kid().map(str::to_string);

        encode(&header, &claims, &self.keys.auth_server.encoding_key()).expect("sign auth jwt")
    }
}

impl TestKeys {
    pub fn auth_jwt_minter(&self) -> TestAuthJwtMinter {
        TestAuthJwtMinter::new(self.clone())
    }

    pub fn resource_token_signer(&self) -> Ed25519ResourceTokenSigner {
        Ed25519ResourceTokenSigner::new(self.resource.clone())
    }
}

#[async_trait]
pub trait ResourceTokenSigner: Send + Sync {
    async fn sign_resource_token(
        &self,
        header: Header,
        claims: ResourceClaims,
    ) -> Result<String, String>;
}

pub struct Ed25519ResourceTokenSigner {
    key: Ed25519KeyPair,
}

impl Ed25519ResourceTokenSigner {
    pub fn new(key: Ed25519KeyPair) -> Self {
        Self { key }
    }
}

#[async_trait]
impl ResourceTokenSigner for Ed25519ResourceTokenSigner {
    async fn sign_resource_token(
        &self,
        mut header: Header,
        claims: ResourceClaims,
    ) -> Result<String, String> {
        if header.kid.is_none() {
            header.kid = self.key.kid().map(str::to_string);
        }
        encode(&header, &claims, &self.key.encoding_key()).map_err(|e| e.to_string())
    }
}

pub fn mint_auth_jwt(
    keys: &TestKeys,
    iss: &str,
    aud: &str,
    agent: &str,
    sub: Option<&str>,
    scope: Option<&str>,
) -> String {
    keys.auth_jwt_minter()
        .mint_auth_jwt(iss, aud, agent, sub, scope)
}
