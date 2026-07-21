use async_trait::async_trait;
use jsonwebtoken::jwk::JwkSet;

use crate::error::{MetadataError, Result};

#[async_trait]
pub trait MetadataFetcher: Send + Sync {
    async fn resolve_jwks_uri(&self, iss: &str, dwk: &str) -> Result<String>;
    async fn fetch_jwks(&self, jwks_uri: &str) -> Result<JwkSet>;
}

/// Fixed JWKS for tests and examples without HTTP metadata discovery.
#[derive(Clone)]
pub struct StaticMetadataFetcher {
    jwks_uri: String,
    jwks: JwkSet,
}

impl StaticMetadataFetcher {
    pub fn new(jwks_uri: impl Into<String>, jwks: JwkSet) -> Self {
        Self {
            jwks_uri: jwks_uri.into(),
            jwks,
        }
    }
}

#[async_trait]
impl MetadataFetcher for StaticMetadataFetcher {
    async fn resolve_jwks_uri(&self, _iss: &str, _dwk: &str) -> Result<String> {
        Ok(self.jwks_uri.clone())
    }

    async fn fetch_jwks(&self, jwks_uri: &str) -> Result<JwkSet> {
        if jwks_uri == self.jwks_uri {
            Ok(self.jwks.clone())
        } else {
            Err(MetadataError::UnknownJwksUri(jwks_uri.to_string()).into())
        }
    }
}
