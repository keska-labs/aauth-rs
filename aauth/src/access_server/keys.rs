use crate::jwt::{AuthJwtMintParams, encode_auth_jwt};
use crate::keys::TestKeys;

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
        encode_auth_jwt(AuthJwtMintParams {
            encoding_key: &self.keys.access_server.encoding_key(),
            kid: self.keys.access_server.kid(),
            dwk: "aauth-access.json",
            iss,
            aud,
            agent,
            agent_jwk: self.keys.agent_ephemeral.public_jwk(),
            sub,
            scope,
        })
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
