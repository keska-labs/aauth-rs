use std::collections::HashMap;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use aauth::MetadataError;
use aauth::error::Result;
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

        let response = self.client.get(metadata_url).send().await.map_err(|e| {
            MetadataError::Request {
                url: metadata_url.to_string(),
                source: Box::new(e),
            }
        })?;

        if !response.status().is_success() {
            return Err(MetadataError::HttpStatus {
                url: metadata_url.to_string(),
                status: response.status().as_u16(),
            }
            .into());
        }

        let bytes = response.bytes().await.map_err(|e| MetadataError::Request {
            url: metadata_url.to_string(),
            source: Box::new(e),
        })?;
        let metadata: AgentProviderMetadata =
            serde_json::from_slice(&bytes).map_err(|e| MetadataError::Decode {
                url: metadata_url.to_string(),
                source: e,
            })?;
        if metadata.jwks_uri.is_empty() {
            return Err(MetadataError::MissingJwksUri {
                url: metadata_url.to_string(),
            }
            .into());
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
            return Err(MetadataError::RateLimited {
                jwks_uri: jwks_uri.to_string(),
            }
            .into());
        }
        self.cache.record_fetch(jwks_uri);

        let response = self.client.get(jwks_uri).send().await.map_err(|e| {
            MetadataError::Request {
                url: jwks_uri.to_string(),
                source: Box::new(e),
            }
        })?;

        if !response.status().is_success() {
            return Err(MetadataError::HttpStatus {
                url: jwks_uri.to_string(),
                status: response.status().as_u16(),
            }
            .into());
        }

        let bytes = response.bytes().await.map_err(|e| MetadataError::Request {
            url: jwks_uri.to_string(),
            source: Box::new(e),
        })?;
        let jwks: JwkSet = serde_json::from_slice(&bytes).map_err(|e| MetadataError::Decode {
            url: jwks_uri.to_string(),
            source: e,
        })?;
        self.cache
            .jwks
            .lock()
            .unwrap()
            .insert(jwks_uri.to_string(), jwks.clone());
        Ok(jwks)
    }
}
