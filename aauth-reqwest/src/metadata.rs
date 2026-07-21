use std::collections::HashMap;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use aauth::error::{AAuthError, Result};
use aauth::metadata::MetadataFetcher;
use aauth::protocol::AgentProviderMetadata;
use async_trait::async_trait;
use jsonwebtoken::jwk::JwkSet;
use reqwest::Client;

const METADATA_CACHE_TTL: Duration = Duration::from_secs(600);
const MIN_FETCH_INTERVAL: Duration = Duration::from_secs(60);

#[derive(Clone)]
struct CacheEntry {
    jwks_uri: String,
    fetched_at: Instant,
}

#[derive(Clone)]
struct MetadataCache {
    metadata: Arc<Mutex<HashMap<String, CacheEntry>>>,
    jwks: Arc<Mutex<HashMap<String, JwkSet>>>,
    last_fetch: Arc<Mutex<HashMap<String, Instant>>>,
}

impl MetadataCache {
    fn new() -> Self {
        Self {
            metadata: Arc::new(Mutex::new(HashMap::new())),
            jwks: Arc::new(Mutex::new(HashMap::new())),
            last_fetch: Arc::new(Mutex::new(HashMap::new())),
        }
    }

    fn clear(&self) {
        self.metadata.lock().unwrap().clear();
        self.jwks.lock().unwrap().clear();
        self.last_fetch.lock().unwrap().clear();
    }

    fn can_fetch(&self, key: &str) -> bool {
        let map = self.last_fetch.lock().unwrap();
        match map.get(key) {
            Some(last) => last.elapsed() >= MIN_FETCH_INTERVAL,
            None => true,
        }
    }

    fn record_fetch(&self, key: &str) {
        self.last_fetch
            .lock()
            .unwrap()
            .insert(key.to_string(), Instant::now());
    }
}

/// HTTP metadata discovery with per-instance caching and rate limiting.
#[derive(Clone)]
pub struct CachedMetadataFetcher {
    client: Client,
    cache: MetadataCache,
}

impl CachedMetadataFetcher {
    pub fn new(client: Client) -> Self {
        Self {
            client,
            cache: MetadataCache::new(),
        }
    }

    pub fn clear_cache(&self) {
        self.cache.clear();
    }

    async fn fetch_metadata(&self, metadata_url: &str) -> Result<AgentProviderMetadata> {
        if let Some(entry) = self.cache.metadata.lock().unwrap().get(metadata_url) {
            if entry.fetched_at.elapsed() < METADATA_CACHE_TTL {
                return Ok(AgentProviderMetadata::from_jwks_uri(entry.jwks_uri.clone()));
            }
        }

        if !self.cache.can_fetch(metadata_url) {
            if let Some(entry) = self.cache.metadata.lock().unwrap().get(metadata_url) {
                return Ok(AgentProviderMetadata::from_jwks_uri(entry.jwks_uri.clone()));
            }
        }

        self.cache.record_fetch(metadata_url);

        let response = self
            .client
            .get(metadata_url)
            .send()
            .await
            .map_err(|e| AAuthError::Message(e.to_string()))?;

        if !response.status().is_success() {
            return Err(AAuthError::Token {
                code: "metadata_fetch_failed".into(),
                message: format!(
                    "Failed to fetch metadata from {metadata_url}: {}",
                    response.status()
                ),
            });
        }

        let metadata: AgentProviderMetadata = response
            .json()
            .await
            .map_err(|e| AAuthError::Message(e.to_string()))?;
        if metadata.jwks_uri.is_empty() {
            return Err(AAuthError::Token {
                code: "metadata_fetch_failed".into(),
                message: format!("No jwks_uri in metadata from {metadata_url}"),
            });
        }

        self.cache.metadata.lock().unwrap().insert(
            metadata_url.to_string(),
            CacheEntry {
                jwks_uri: metadata.jwks_uri.clone(),
                fetched_at: Instant::now(),
            },
        );

        Ok(metadata)
    }
}

#[async_trait]
impl MetadataFetcher for CachedMetadataFetcher {
    async fn resolve_jwks_uri(&self, iss: &str, dwk: &str) -> Result<String> {
        let iss = iss.trim_end_matches('/');
        let metadata_url = format!("{iss}/.well-known/{dwk}");
        let metadata = self.fetch_metadata(&metadata_url).await?;
        Ok(metadata.jwks_uri)
    }

    async fn fetch_jwks(&self, jwks_uri: &str) -> Result<JwkSet> {
        if let Some(cached) = self.cache.jwks.lock().unwrap().get(jwks_uri) {
            return Ok(cached.clone());
        }

        if !self.cache.can_fetch(jwks_uri) {
            if let Some(cached) = self.cache.jwks.lock().unwrap().get(jwks_uri) {
                return Ok(cached.clone());
            }
            return Err(AAuthError::Token {
                code: "metadata_fetch_failed".into(),
                message: format!("JWKS fetch rate limited for {jwks_uri}"),
            });
        }
        self.cache.record_fetch(jwks_uri);

        let response = self
            .client
            .get(jwks_uri)
            .send()
            .await
            .map_err(|e| AAuthError::Message(e.to_string()))?;

        if !response.status().is_success() {
            return Err(AAuthError::Token {
                code: "invalid_agent_token".into(),
                message: format!(
                    "Failed to fetch JWKS from {jwks_uri}: {}",
                    response.status()
                ),
            });
        }

        let jwks: JwkSet = response
            .json()
            .await
            .map_err(|e| AAuthError::Message(e.to_string()))?;
        self.cache
            .jwks
            .lock()
            .unwrap()
            .insert(jwks_uri.to_string(), jwks.clone());
        Ok(jwks)
    }
}
