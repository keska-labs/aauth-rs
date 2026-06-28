#[cfg(feature = "client")]
use std::sync::Arc;

#[cfg(feature = "client")]
use crate::client::KeyMaterialProvider;
use crate::error::Result;
use crate::jwt::{
    jwk_set_from_okp, jwk_thumbprint, ActClaim, AgentClaims, AuthClaims, CnfClaim, OkpJwk,
    OkpSigningJwk,
};
use crate::metadata::StaticMetadataFetcher;
#[cfg(feature = "server")]
use crate::server::SignFn;
use crate::types::{JwtTyp, KeyMaterial, SignatureKey, SignatureKeyJwt};
use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine as _};
use ed25519_dalek::pkcs8::EncodePrivateKey;
use ed25519_dalek::{SigningKey, VerifyingKey};
use jsonwebtoken::{encode, Algorithm, EncodingKey, Header, jwk::JwkSet};
use rand::rngs::OsRng;
use uuid::Uuid;

#[cfg(feature = "client")]
use async_trait::async_trait;

#[derive(Clone)]
pub struct Ed25519KeyPair {
    signing_key: SigningKey,
    verifying_key: VerifyingKey,
    kid: Option<String>,
    thumbprint: String,
}

impl Ed25519KeyPair {
    pub fn generate() -> Self {
        let signing_key = SigningKey::generate(&mut OsRng);
        let verifying_key = signing_key.verifying_key();
        let public_jwk = Self::public_jwk_for(&verifying_key, None);
        let thumbprint = jwk_thumbprint(&public_jwk).expect("thumbprint");
        Self {
            signing_key,
            verifying_key,
            kid: None,
            thumbprint,
        }
    }

    pub fn generate_with_kid(kid: &str) -> Self {
        let signing_key = SigningKey::generate(&mut OsRng);
        let verifying_key = signing_key.verifying_key();
        let public_jwk = Self::public_jwk_for(&verifying_key, Some(kid));
        let thumbprint = jwk_thumbprint(&public_jwk).expect("thumbprint");
        Self {
            signing_key,
            verifying_key,
            kid: Some(kid.to_string()),
            thumbprint,
        }
    }

    pub fn thumbprint(&self) -> &str {
        &self.thumbprint
    }

    pub fn public_jwk(&self) -> OkpJwk {
        Self::public_jwk_for(&self.verifying_key, self.kid.as_deref())
    }

    pub fn signing_jwk(&self) -> OkpSigningJwk {
        OkpSigningJwk {
            kty: "OKP".into(),
            crv: "Ed25519".into(),
            x: URL_SAFE_NO_PAD.encode(self.verifying_key.as_bytes()),
            d: URL_SAFE_NO_PAD.encode(self.signing_key.to_bytes()),
            kid: self.kid.clone(),
        }
    }

    pub fn encoding_key(&self) -> EncodingKey {
        let der = self.signing_key.to_pkcs8_der().expect("pkcs8 encode");
        EncodingKey::from_ed_der(der.as_bytes())
    }

    pub fn jwk_set(&self) -> JwkSet {
        jwk_set_from_okp(&[self.public_jwk()]).expect("valid jwk set")
    }

    fn public_jwk_for(key: &VerifyingKey, kid: Option<&str>) -> OkpJwk {
        OkpJwk {
            kty: "OKP".into(),
            crv: "Ed25519".into(),
            x: URL_SAFE_NO_PAD.encode(key.as_bytes()),
            kid: kid.map(str::to_string),
        }
    }
}

#[derive(Clone)]
pub struct TestKeys {
    pub agent_root: Ed25519KeyPair,
    pub agent_ephemeral: Ed25519KeyPair,
    pub auth_server: Ed25519KeyPair,
    pub resource: Ed25519KeyPair,
}

pub fn create_test_keys() -> TestKeys {
    TestKeys {
        agent_root: Ed25519KeyPair::generate_with_kid("agent-root-1"),
        agent_ephemeral: Ed25519KeyPair::generate(),
        auth_server: Ed25519KeyPair::generate_with_kid("auth-1"),
        resource: Ed25519KeyPair::generate_with_kid("resource-1"),
    }
}

pub fn mint_agent_jwt(keys: &TestKeys, agent_url: &str, sub: &str) -> String {
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
            jwk: keys.agent_ephemeral.public_jwk(),
        },
        iat: now,
        exp: now + 3600,
        ps: None,
    };

    let mut header = Header::new(Algorithm::EdDSA);
    header.typ = Some(JwtTyp::Agent.as_str().into());
    header.kid = keys.agent_root.kid.clone();

    encode(&header, &claims, &keys.agent_root.encoding_key()).expect("sign agent jwt")
}

pub fn mint_auth_jwt(
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
            jwk: keys.agent_ephemeral.public_jwk(),
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
    header.kid = keys.auth_server.kid.clone();

    encode(&header, &claims, &keys.auth_server.encoding_key()).expect("sign auth jwt")
}

pub struct StaticKeyMaterialProvider {
    material: KeyMaterial,
}

impl StaticKeyMaterialProvider {
    pub fn new(keys: &TestKeys, agent_jwt: String) -> Self {
        Self {
            material: KeyMaterial {
                signing_jwk: keys.agent_ephemeral.signing_jwk(),
                signature_key: SignatureKey::Jwt(SignatureKeyJwt { jwt: agent_jwt }),
            },
        }
    }
}

#[cfg(feature = "client")]
#[async_trait]
impl KeyMaterialProvider for StaticKeyMaterialProvider {
    async fn key_material(&self) -> Result<KeyMaterial> {
        Ok(self.material.clone())
    }
}

#[cfg(feature = "client")]
pub fn create_key_provider(
    keys: &TestKeys,
    agent_jwt: String,
) -> Arc<dyn KeyMaterialProvider> {
    Arc::new(StaticKeyMaterialProvider::new(keys, agent_jwt))
}

#[cfg(feature = "server")]
pub fn resource_sign_fn(keys: &TestKeys) -> SignFn {
    let encoding = keys.resource.encoding_key();
    let kid = keys.resource.kid.clone();
    Box::new(move |mut header, claims| {
        let encoding = encoding.clone();
        if header.kid.is_none() {
            header.kid = kid.clone();
        }
        Box::pin(async move {
            encode(&header, &claims, &encoding).map_err(|e| e.to_string())
        })
    })
}

pub fn static_agent_metadata_fetcher(keys: &TestKeys, agent_url: &str) -> StaticMetadataFetcher {
    StaticMetadataFetcher::new(
        format!("{agent_url}/jwks"),
        keys.agent_root.jwk_set(),
    )
}

pub fn static_auth_metadata_fetcher(keys: &TestKeys, auth_server_url: &str) -> StaticMetadataFetcher {
    StaticMetadataFetcher::new(
        format!("{auth_server_url}/jwks"),
        keys.auth_server.jwk_set(),
    )
}
