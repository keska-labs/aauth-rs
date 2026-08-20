use std::collections::HashMap;
use std::sync::{Mutex, OnceLock};

use crate::agent_token::sign_agent_token;
use crate::config::{get_agent_config, list_agent_providers};
use crate::error::{Error, Result};
use crate::types::{AgentTokenResult, SignAgentTokenOptions};

#[derive(Debug, Clone, Default)]
pub struct CreateAgentTokenOptions {
    pub agent_url: Option<String>,
    pub agent_id: Option<String>,
    pub local: Option<String>,
    pub token_lifetime: Option<u64>,
    pub person_server_url: Option<String>,
}

struct CacheEntry {
    result: AgentTokenResult,
    expires_at: i64,
}

fn token_cache() -> &'static Mutex<HashMap<String, CacheEntry>> {
    static CACHE: OnceLock<Mutex<HashMap<String, CacheEntry>>> = OnceLock::new();
    CACHE.get_or_init(|| Mutex::new(HashMap::new()))
}

fn mint_lock() -> &'static tokio::sync::Mutex<()> {
    static LOCK: OnceLock<tokio::sync::Mutex<()>> = OnceLock::new();
    LOCK.get_or_init(|| tokio::sync::Mutex::new(()))
}

fn cache_get(cache_key: &str) -> Result<Option<AgentTokenResult>> {
    let cache = token_cache()
        .lock()
        .map_err(|_| Error::msg("token cache lock poisoned"))?;
    if let Some(entry) = cache.get(cache_key) {
        let now = now_secs();
        if now < entry.expires_at {
            return Ok(Some(entry.result.clone()));
        }
    }
    Ok(None)
}

/// Create an agent token with caching (mirrors `@aauth/local-keys` `createAgentToken`).
pub async fn create_agent_token(options: CreateAgentTokenOptions) -> Result<AgentTokenResult> {
    let token_lifetime = options.token_lifetime.unwrap_or(3600);

    let agent_url = match options.agent_url {
        Some(u) => u,
        None => list_agent_providers()
            .into_iter()
            .next()
            .ok_or(Error::NoAgentUrl)?,
    };

    let agent_id = if let Some(id) = options.agent_id {
        id
    } else if let Some(local) = options.local {
        let host = url::Url::parse(&agent_url)
            .map_err(|e| Error::msg(format!("invalid agent URL: {e}")))?
            .host_str()
            .ok_or_else(|| Error::msg("agent URL missing host"))?
            .to_string();
        format!("aauth:{local}@{host}")
    } else {
        get_agent_config(&agent_url)
            .and_then(|c| c.agent_id)
            .ok_or_else(|| Error::NoAgentId(agent_url.clone()))?
    };

    let cache_key = format!(
        "{agent_url}::{agent_id}::{}",
        options.person_server_url.as_deref().unwrap_or("")
    );

    if let Some(hit) = cache_get(&cache_key)? {
        return Ok(hit);
    }

    // Single-flight mint so concurrent callers share one ephemeral key + JWT pair.
    let _mint = mint_lock().lock().await;
    if let Some(hit) = cache_get(&cache_key)? {
        return Ok(hit);
    }

    let result = sign_agent_token(SignAgentTokenOptions {
        agent_url,
        sub: agent_id,
        lifetime: Some(token_lifetime),
        person_server_url: options.person_server_url,
    })
    .await?;

    let now = now_secs();
    let expires_at = now + (token_lifetime as i64 * 8 / 10);
    token_cache()
        .lock()
        .map_err(|_| Error::msg("token cache lock poisoned"))?
        .insert(
            cache_key,
            CacheEntry {
                result: result.clone(),
                expires_at,
            },
        );

    Ok(result)
}

fn now_secs() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0)
}
