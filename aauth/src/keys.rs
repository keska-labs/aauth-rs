use crate::jwt::{jwk_set_from_okp, jwk_thumbprint, OkpJwk, OkpSigningJwk};
use crate::metadata::StaticMetadataFetcher;
use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine as _};
use ed25519_dalek::pkcs8::EncodePrivateKey;
use ed25519_dalek::{SigningKey, VerifyingKey};
use jsonwebtoken::{EncodingKey, jwk::JwkSet};
use rand::rngs::OsRng;

pub trait OkpSigningKey: Clone + Send + Sync {
    fn thumbprint(&self) -> &str;
    fn kid(&self) -> Option<&str>;
    fn public_jwk(&self) -> OkpJwk;
    fn signing_jwk(&self) -> OkpSigningJwk;
    fn encoding_key(&self) -> EncodingKey;
    fn jwk_set(&self) -> JwkSet;
}

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

    pub fn kid(&self) -> Option<&str> {
        self.kid.as_deref()
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

impl OkpSigningKey for Ed25519KeyPair {
    fn thumbprint(&self) -> &str {
        Ed25519KeyPair::thumbprint(self)
    }

    fn kid(&self) -> Option<&str> {
        Ed25519KeyPair::kid(self)
    }

    fn public_jwk(&self) -> OkpJwk {
        Ed25519KeyPair::public_jwk(self)
    }

    fn signing_jwk(&self) -> OkpSigningJwk {
        Ed25519KeyPair::signing_jwk(self)
    }

    fn encoding_key(&self) -> EncodingKey {
        Ed25519KeyPair::encoding_key(self)
    }

    fn jwk_set(&self) -> JwkSet {
        Ed25519KeyPair::jwk_set(self)
    }
}

#[derive(Clone)]
pub struct TestKeys {
    pub agent_root: Ed25519KeyPair,
    pub agent_ephemeral: Ed25519KeyPair,
    pub auth_server: Ed25519KeyPair,
    pub resource: Ed25519KeyPair,
}

impl TestKeys {
    pub fn generate() -> Self {
        Self {
            agent_root: Ed25519KeyPair::generate_with_kid("agent-root-1"),
            agent_ephemeral: Ed25519KeyPair::generate(),
            auth_server: Ed25519KeyPair::generate_with_kid("auth-1"),
            resource: Ed25519KeyPair::generate_with_kid("resource-1"),
        }
    }

    pub fn agent_metadata_fetcher(&self, agent_url: &str) -> StaticMetadataFetcher {
        StaticMetadataFetcher::new(
            format!("{agent_url}/jwks"),
            self.agent_root.jwk_set(),
        )
    }

    pub fn auth_metadata_fetcher(&self, auth_server_url: &str) -> StaticMetadataFetcher {
        StaticMetadataFetcher::new(
            format!("{auth_server_url}/jwks"),
            self.auth_server.jwk_set(),
        )
    }
}

pub fn create_test_keys() -> TestKeys {
    TestKeys::generate()
}

pub fn static_agent_metadata_fetcher(
    keys: &TestKeys,
    agent_url: &str,
) -> StaticMetadataFetcher {
    keys.agent_metadata_fetcher(agent_url)
}

pub fn static_auth_metadata_fetcher(
    keys: &TestKeys,
    auth_server_url: &str,
) -> StaticMetadataFetcher {
    keys.auth_metadata_fetcher(auth_server_url)
}
