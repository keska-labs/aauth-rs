use jsonwebtoken::{Algorithm, Header, encode};
use uuid::Uuid;

use crate::jwt::{AuthClaims, CnfClaim};
use crate::keys::TestKeys;
use crate::protocol::JwtTyp;

pub trait AccessAuthJwtMinter: Send + Sync {
    fn mint_access_auth_jwt(
        &self,
        iss: &str,
        aud: &str,
        agent: &str,
        sub: Option<&str>,
        scope: Option<&str>,
    ) -> String;
}

#[derive(Clone)]
pub struct TestAccessAuthJwtMinter {
    keys: TestKeys,
}

impl TestAccessAuthJwtMinter {
    pub fn new(keys: TestKeys) -> Self {
        Self { keys }
    }
}

impl AccessAuthJwtMinter for TestAccessAuthJwtMinter {
    fn mint_access_auth_jwt(
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
            dwk: "aauth-access.json".into(),
            aud: aud.into(),
            jti: Uuid::new_v4().to_string(),
            agent: agent.into(),
            act: None,
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
        header.kid = self.keys.access_server.kid().map(str::to_string);

        encode(&header, &claims, &self.keys.access_server.encoding_key())
            .expect("sign access auth jwt")
    }
}

impl TestKeys {
    pub fn access_auth_jwt_minter(&self) -> TestAccessAuthJwtMinter {
        TestAccessAuthJwtMinter::new(self.clone())
    }
}

pub fn mint_access_auth_jwt(
    keys: &TestKeys,
    iss: &str,
    aud: &str,
    agent: &str,
    sub: Option<&str>,
    scope: Option<&str>,
) -> String {
    keys.access_auth_jwt_minter()
        .mint_access_auth_jwt(iss, aud, agent, sub, scope)
}
