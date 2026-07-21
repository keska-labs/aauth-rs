use crate::error::Result;
use crate::jwt::{AuthJwtMintParams, PublicJwk, SigningJwk, encode_auth_jwt};
use crate::keys::TestKeys;

pub trait PersonAuthJwtMinter: Send + Sync {
    fn mint_person_auth_jwt(
        &self,
        iss: &str,
        aud: &str,
        agent: &str,
        agent_jwk: &PublicJwk,
        sub: Option<&str>,
        scope: Option<&str>,
    ) -> Result<String>;
}

#[derive(Clone)]
pub struct TestPersonAuthJwtMinter {
    keys: TestKeys,
}

impl TestPersonAuthJwtMinter {
    pub fn new(keys: TestKeys) -> Self {
        Self { keys }
    }
}

impl PersonAuthJwtMinter for TestPersonAuthJwtMinter {
    fn mint_person_auth_jwt(
        &self,
        iss: &str,
        aud: &str,
        agent: &str,
        agent_jwk: &PublicJwk,
        sub: Option<&str>,
        scope: Option<&str>,
    ) -> Result<String> {
        encode_auth_jwt(AuthJwtMintParams {
            encoding_key: &self.keys.person_server.encoding_key(),
            kid: self.keys.person_server.kid(),
            dwk: "aauth-person.json",
            iss,
            aud,
            agent,
            agent_jwk: agent_jwk.clone(),
            sub,
            scope,
        })
    }
}

impl TestKeys {
    pub fn person_auth_jwt_minter(&self) -> TestPersonAuthJwtMinter {
        TestPersonAuthJwtMinter::new(self.clone())
    }

    pub fn mint_person_auth_jwt(
        &self,
        iss: &str,
        aud: &str,
        agent: &str,
        sub: Option<&str>,
        scope: Option<&str>,
    ) -> String {
        PersonAuthJwtMinter::mint_person_auth_jwt(
            &self.person_auth_jwt_minter(),
            iss,
            aud,
            agent,
            &self.agent_ephemeral.public_jwk(),
            sub,
            scope,
        )
        .expect("mint person auth jwt")
    }
}

/// Mint a short-lived agent JWT for the Person Server to use in outbound HTTP signatures.
pub fn mint_person_server_signature_jwt(keys: &TestKeys, person_server_url: &str) -> String {
    use jsonwebtoken::{Algorithm, Header, encode};
    use uuid::Uuid;

    use crate::jwt::{AgentClaims, CnfClaim};
    use crate::protocol::JwtTyp;

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

    encode(&header, &claims, &keys.person_server.encoding_key())
        .expect("sign person server signature jwt")
}

/// Person Server outbound signer for federation requests to an Access Server.
#[derive(Clone)]
pub struct PersonServerOutboundSigner {
    pub person_server_url: String,
    pub signing_jwk: SigningJwk,
    pub keys: TestKeys,
}

impl PersonServerOutboundSigner {
    pub fn new(keys: TestKeys, person_server_url: impl Into<String>) -> Self {
        let person_server_url = person_server_url.into();
        let signing_jwk = keys.person_server.signing_jwk();
        Self {
            person_server_url,
            signing_jwk,
            keys,
        }
    }

    pub fn signature_jwt(&self) -> String {
        mint_person_server_signature_jwt(&self.keys, &self.person_server_url)
    }

    pub fn signing_jwk(&self) -> &SigningJwk {
        &self.signing_jwk
    }
}
