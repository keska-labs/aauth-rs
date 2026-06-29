use jsonwebtoken::{Algorithm, Header, encode};
use uuid::Uuid;

use crate::jwt::{AgentClaims, AuthClaims, CnfClaim};
use crate::keys::TestKeys;
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
        header.kid = self.keys.person_server.kid().map(str::to_string);

        encode(&header, &claims, &self.keys.person_server.encoding_key()).expect("sign auth jwt")
    }
}

impl TestKeys {
    pub fn auth_jwt_minter(&self) -> TestAuthJwtMinter {
        TestAuthJwtMinter::new(self.clone())
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

/// Mint a short-lived agent JWT for the Person Server to use in outbound HTTP signatures.
pub fn mint_person_server_signature_jwt(keys: &TestKeys, person_server_url: &str) -> String {
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs() as i64;

    let claims = AgentClaims {
        iss: person_server_url.into(),
        dwk: "aauth-person.json".into(),
        sub: person_server_url.into(),
        jti: Uuid::new_v4().to_string(),
        cnf: CnfClaim {
            jwk: keys.person_server.public_jwk(),
        },
        iat: now,
        exp: now + 3600,
        ps: None,
        parent_agent: None,
    };

    let mut header = Header::new(Algorithm::EdDSA);
    header.typ = Some(JwtTyp::Agent.as_str().into());
    header.kid = keys.person_server.kid().map(str::to_string);

    encode(
        &header,
        &claims,
        &keys.person_server.encoding_key(),
    )
    .expect("sign person server signature jwt")
}
