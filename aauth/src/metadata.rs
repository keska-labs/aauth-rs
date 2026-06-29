use std::collections::HashMap;
use std::sync::Mutex;
use std::time::{Duration, Instant};

use async_trait::async_trait;
use jsonwebtoken::jwk::JwkSet;
use reqwest::Client;

use crate::error::Result;
use crate::types::MetadataDocument;

const METADATA_CACHE_TTL: Duration = Duration::from_secs(600);
const MIN_FETCH_INTERVAL: Duration = Duration::from_secs(60);

#[derive(Clone)]
struct CacheEntry {
    jwks_uri: String,
    fetched_at: Instant,
}

static METADATA_CACHE: std::sync::OnceLock<Mutex<HashMap<String, CacheEntry>>> =
    std::sync::OnceLock::new();

static LAST_FETCH: std::sync::OnceLock<Mutex<HashMap<String, Instant>>> =
    std::sync::OnceLock::new();

fn metadata_cache() -> &'static Mutex<HashMap<String, CacheEntry>> {
    METADATA_CACHE.get_or_init(|| Mutex::new(HashMap::new()))
}

fn last_fetch_map() -> &'static Mutex<HashMap<String, Instant>> {
    LAST_FETCH.get_or_init(|| Mutex::new(HashMap::new()))
}

static JWKS_CACHE: std::sync::OnceLock<Mutex<HashMap<String, JwkSet>>> = std::sync::OnceLock::new();

fn jwks_cache() -> &'static Mutex<HashMap<String, JwkSet>> {
    JWKS_CACHE.get_or_init(|| Mutex::new(HashMap::new()))
}

pub fn clear_metadata_cache() {
    metadata_cache().lock().unwrap().clear();
    last_fetch_map().lock().unwrap().clear();
    jwks_cache().lock().unwrap().clear();
}

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
            Err(crate::error::AAuthError::Token {
                code: "metadata_fetch_failed".into(),
                message: format!("unknown JWKS URI: {jwks_uri}"),
            })
        }
    }
}

#[derive(Clone)]
pub struct CachedMetadataFetcher {
    client: Client,
}

impl CachedMetadataFetcher {
    pub fn new(client: Client) -> Self {
        Self { client }
    }

    async fn fetch_metadata(&self, metadata_url: &str) -> Result<MetadataDocument> {
        if let Some(entry) = metadata_cache().lock().unwrap().get(metadata_url) {
            if entry.fetched_at.elapsed() < METADATA_CACHE_TTL {
                return Ok(MetadataDocument {
                    jwks_uri: entry.jwks_uri.clone(),
                    extra: HashMap::new(),
                });
            }
        }

        if !can_fetch(metadata_url) {
            if let Some(entry) = metadata_cache().lock().unwrap().get(metadata_url) {
                return Ok(MetadataDocument {
                    jwks_uri: entry.jwks_uri.clone(),
                    extra: HashMap::new(),
                });
            }
        }

        record_fetch(metadata_url);

        let response = self
            .client
            .get(metadata_url)
            .send()
            .await
            .map_err(|e| crate::error::AAuthError::Message(e.to_string()))?;

        if !response.status().is_success() {
            return Err(crate::error::AAuthError::Token {
                code: "metadata_fetch_failed".into(),
                message: format!(
                    "Failed to fetch metadata from {metadata_url}: {}",
                    response.status()
                ),
            });
        }

        let metadata: MetadataDocument = response
            .json()
            .await
            .map_err(|e| crate::error::AAuthError::Message(e.to_string()))?;
        if metadata.jwks_uri.is_empty() {
            return Err(crate::error::AAuthError::Token {
                code: "metadata_fetch_failed".into(),
                message: format!("No jwks_uri in metadata from {metadata_url}"),
            });
        }

        metadata_cache().lock().unwrap().insert(
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
        if let Some(cached) = jwks_cache().lock().unwrap().get(jwks_uri) {
            return Ok(cached.clone());
        }

        if !can_fetch(jwks_uri) {
            if let Some(cached) = jwks_cache().lock().unwrap().get(jwks_uri) {
                return Ok(cached.clone());
            }
            return Err(crate::error::AAuthError::Token {
                code: "metadata_fetch_failed".into(),
                message: format!("JWKS fetch rate limited for {jwks_uri}"),
            });
        }
        record_fetch(jwks_uri);

        let response = self
            .client
            .get(jwks_uri)
            .send()
            .await
            .map_err(|e| crate::error::AAuthError::Message(e.to_string()))?;

        if !response.status().is_success() {
            return Err(crate::error::AAuthError::Token {
                code: "invalid_agent_token".into(),
                message: format!("Failed to fetch JWKS from {jwks_uri}: {}", response.status()),
            });
        }

        let jwks: JwkSet = response
            .json()
            .await
            .map_err(|e| crate::error::AAuthError::Message(e.to_string()))?;
        jwks_cache()
            .lock()
            .unwrap()
            .insert(jwks_uri.to_string(), jwks.clone());
        Ok(jwks)
    }
}

fn can_fetch(key: &str) -> bool {
    let map = last_fetch_map().lock().unwrap();
    match map.get(key) {
        Some(last) => last.elapsed() >= MIN_FETCH_INTERVAL,
        None => true,
    }
}

fn record_fetch(key: &str) {
    last_fetch_map()
        .lock()
        .unwrap()
        .insert(key.to_string(), Instant::now());
}
