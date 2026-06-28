use std::sync::Arc;

use aauth::client::KeyMaterialProvider;
use aauth::error::Result;
use aauth::jwt::{jwk_thumbprint, ActClaim, AgentClaims, AuthClaims, CnfClaim, OkpJwk};
use aauth::types::{JwtTyp, KeyMaterial, SignatureKey, SignatureKeyJwt};
use async_trait::async_trait;
use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine as _};
use ed25519_dalek::{SigningKey, VerifyingKey};
use jsonwebtoken::{encode, Algorithm, EncodingKey, Header};
use rand::rngs::OsRng;
use serde_json::{json, Value};
use uuid::Uuid;

#[derive(Clone)]
pub struct TestKeyPair {
    pub signing_key: SigningKey,
    pub verifying_key: VerifyingKey,
    pub pub_jwk: Value,
    pub priv_jwk: Value,
    pub thumbprint: String,
}

impl TestKeyPair {
    pub fn generate() -> Self {
        let signing_key = SigningKey::generate(&mut OsRng);
        let verifying_key = signing_key.verifying_key();
        let pub_jwk = ed25519_public_jwk(&verifying_key, None);
        let priv_jwk = ed25519_private_jwk(&signing_key, &verifying_key);
        let thumbprint = jwk_thumbprint(&okp_jwk(&pub_jwk)).expect("thumbprint");
        Self {
            signing_key,
            verifying_key,
            pub_jwk,
            priv_jwk,
            thumbprint,
        }
    }

    pub fn generate_with_kid(kid: &str) -> Self {
        let signing_key = SigningKey::generate(&mut OsRng);
        let verifying_key = signing_key.verifying_key();
        let pub_jwk = ed25519_public_jwk(&verifying_key, Some(kid));
        let priv_jwk = ed25519_private_jwk(&signing_key, &verifying_key);
        let thumbprint = jwk_thumbprint(&okp_jwk(&pub_jwk)).expect("thumbprint");
        Self {
            signing_key,
            verifying_key,
            pub_jwk,
            priv_jwk,
            thumbprint,
        }
    }

    pub fn encoding_key(&self) -> EncodingKey {
        use ed25519_dalek::pkcs8::EncodePrivateKey;
        let der = self.signing_key.to_pkcs8_der().expect("pkcs8 encode");
        EncodingKey::from_ed_der(der.as_bytes())
    }
}

#[derive(Clone)]
pub struct TestKeys {
    pub agent_root: TestKeyPair,
    pub agent_ephemeral: TestKeyPair,
    pub auth_server: TestKeyPair,
    pub resource: TestKeyPair,
}

pub fn create_test_keys() -> TestKeys {
    TestKeys {
        agent_root: TestKeyPair::generate_with_kid("agent-root-1"),
        agent_ephemeral: TestKeyPair::generate(),
        auth_server: TestKeyPair::generate_with_kid("auth-1"),
        resource: TestKeyPair::generate_with_kid("resource-1"),
    }
}

pub fn create_agent_jwt(keys: &TestKeys, agent_url: &str, sub: &str) -> String {
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
            jwk: okp_jwk(&keys.agent_ephemeral.pub_jwk),
        },
        iat: now,
        exp: now + 3600,
        ps: None,
    };

    let mut header = Header::new(Algorithm::EdDSA);
    header.typ = Some(JwtTyp::Agent.as_str().into());
    header.kid = Some("agent-root-1".into());

    encode(&header, &claims, &keys.agent_root.encoding_key()).expect("sign agent jwt")
}

pub fn create_auth_jwt(
    keys: &TestKeys,
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
        act: ActClaim {
            sub: agent.into(),
        },
        cnf: CnfClaim {
            jwk: okp_jwk(&keys.agent_ephemeral.pub_jwk),
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
    header.kid = Some("auth-1".into());

    encode(&header, &claims, &keys.auth_server.encoding_key()).expect("sign auth jwt")
}

pub struct StaticKeyMaterialProvider {
    material: KeyMaterial,
}

impl StaticKeyMaterialProvider {
    pub fn new(keys: &TestKeys, agent_jwt: String) -> Self {
        Self {
            material: KeyMaterial {
                signing_jwk: keys.agent_ephemeral.priv_jwk.clone(),
                signature_key: SignatureKey::Jwt(SignatureKeyJwt { jwt: agent_jwt }),
            },
        }
    }
}

#[async_trait]
impl KeyMaterialProvider for StaticKeyMaterialProvider {
    async fn key_material(&self) -> Result<KeyMaterial> {
        Ok(self.material.clone())
    }
}

pub fn create_key_provider(keys: &TestKeys, agent_jwt: String) -> Arc<dyn KeyMaterialProvider> {
    Arc::new(StaticKeyMaterialProvider::new(keys, agent_jwt))
}

fn okp_jwk(value: &Value) -> OkpJwk {
    serde_json::from_value(value.clone()).expect("valid OKP JWK")
}

fn ed25519_public_jwk(key: &VerifyingKey, kid: Option<&str>) -> Value {
    let x = URL_SAFE_NO_PAD.encode(key.as_bytes());
    let mut jwk = json!({
        "kty": "OKP",
        "crv": "Ed25519",
        "x": x,
    });
    if let Some(kid) = kid {
        jwk["kid"] = json!(kid);
    }
    jwk
}

fn ed25519_private_jwk(signing: &SigningKey, verifying: &VerifyingKey) -> Value {
    let x = URL_SAFE_NO_PAD.encode(verifying.as_bytes());
    let d = URL_SAFE_NO_PAD.encode(signing.to_bytes());
    json!({
        "kty": "OKP",
        "crv": "Ed25519",
        "x": x,
        "d": d,
    })
}

pub fn resource_sign_fn(keys: &TestKeys) -> aauth::server::SignFn {
    let encoding = keys.resource.encoding_key();
    Box::new(move |payload, header| {
        let encoding = encoding.clone();
        Box::pin(async move {
            let alg = header
                .get("alg")
                .and_then(|v| v.as_str())
                .unwrap_or("EdDSA");
            let typ = header
                .get("typ")
                .and_then(|v| v.as_str())
                .map(str::to_string);
            let mut jwt_header = Header::new(match alg {
                "EdDSA" => Algorithm::EdDSA,
                _ => Algorithm::EdDSA,
            });
            jwt_header.typ = typ;
            encode(&jwt_header, &payload, &encoding).map_err(|e| e.to_string())
        })
    })
}

pub fn auth_sign_fn(keys: &TestKeys) -> aauth::server::SignFn {
    resource_sign_fn(keys)
}
