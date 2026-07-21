use std::sync::Arc;

use jsonwebtoken::jwk::JwkSet;

use crate::error::{MetadataError, Result};

#[trait_variant::make(MetadataFetcher: Send)]
#[dynosaur::dynosaur(pub DynMetadataFetcher = dyn(box) MetadataFetcher, bridge(dyn))]
pub trait LocalMetadataFetcher: Sync {
    async fn resolve_jwks_uri(&self, iss: &str, dwk: &str) -> Result<String>;
    async fn fetch_jwks(&self, jwks_uri: &str) -> Result<JwkSet>;
}

impl<T: MetadataFetcher + Sync> MetadataFetcher for Arc<T> {
    async fn resolve_jwks_uri(&self, iss: &str, dwk: &str) -> Result<String> {
        (**self).resolve_jwks_uri(iss, dwk).await
    }

    async fn fetch_jwks(&self, jwks_uri: &str) -> Result<JwkSet> {
        (**self).fetch_jwks(jwks_uri).await
    }
}

impl<T: MetadataFetcher + Sync> MetadataFetcher for &T {
    async fn resolve_jwks_uri(&self, iss: &str, dwk: &str) -> Result<String> {
        (**self).resolve_jwks_uri(iss, dwk).await
    }

    async fn fetch_jwks(&self, jwks_uri: &str) -> Result<JwkSet> {
        (**self).fetch_jwks(jwks_uri).await
    }
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
