use async_trait::async_trait;
use jsonwebtoken::{Header, encode};

use crate::error::ResourceTokenError;
use crate::jwt::ResourceClaims;
use crate::keys::{Ed25519KeyPair, TestKeys};

#[async_trait]
pub trait ResourceTokenSigner: Send + Sync {
    async fn sign_resource_token(
        &self,
        header: Header,
        claims: ResourceClaims,
    ) -> Result<String, ResourceTokenError>;
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
    ) -> Result<String, ResourceTokenError> {
        if header.kid.is_none() {
            header.kid = self.key.kid().map(str::to_string);
        }
        encode(&header, &claims, &self.key.encoding_key()).map_err(ResourceTokenError::Encode)
    }
}

impl TestKeys {
    pub fn resource_token_signer(&self) -> Ed25519ResourceTokenSigner {
        Ed25519ResourceTokenSigner::new(self.resource.clone())
    }
}
