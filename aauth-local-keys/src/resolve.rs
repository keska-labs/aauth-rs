use serde_json::Value;

use crate::backends::{discover_backends, discover_local_keys, get_public_key, LocalKey};
use crate::config::get_agent_config;
use crate::error::{Error, Result};
use crate::types::{LocalKeyMeta, ResolvedKey};

/// Resolve which key to use for signing an agent JWT.
///
/// Fallback chain (hardware preferred):
/// 1. Match published JWKS thumbprints against local keys
/// 2. Config-registered keys
/// 3. First local hardware key
/// 4. First local software key
pub async fn resolve_key(agent_url: &str) -> Result<ResolvedKey> {
    let agent_config = get_agent_config(agent_url);
    let jwks_keys = fetch_agent_jwks(
        agent_url,
        agent_config.as_ref().and_then(|c| c.jwks_uri.as_deref()),
    )
    .await;
    let local_keys = discover_local_keys(agent_url);

    if !jwks_keys.is_empty() && !local_keys.is_empty() {
        if let Some(m) = match_jwks_to_local(&jwks_keys, &local_keys) {
            return Ok(m);
        }
    }

    if let Some(cfg) = &agent_config {
        if !cfg.keys.is_empty() {
            if let Some(m) = resolve_from_config(&cfg.keys, &local_keys) {
                return Ok(m);
            }
        }
    }

    if let Some(k) = local_keys.iter().find(|k| k.backend.is_hardware()) {
        return Ok(to_resolved(k, &k.kid));
    }

    if let Some(k) = local_keys.first() {
        return Ok(to_resolved(k, &k.kid));
    }

    Err(Error::NoSigningKey(agent_url.to_string()))
}

async fn fetch_agent_jwks(agent_url: &str, cached_jwks_uri: Option<&str>) -> Vec<Value> {
    let client = match reqwest::Client::builder()
        .timeout(std::time::Duration::from_secs(5))
        .build()
    {
        Ok(c) => c,
        Err(_) => return Vec::new(),
    };

    let meta_url = format!(
        "{}/.well-known/aauth-agent.json",
        agent_url.trim_end_matches('/')
    );

    if let Some(cached) = cached_jwks_uri {
        let jwks_fut = client.get(cached).send();
        let meta_fut = client.get(&meta_url).send();
        let (jwks_resp, meta_resp) = tokio::join!(jwks_fut, meta_fut);

        if let Ok(meta_resp) = meta_resp {
            if meta_resp.status().is_success() {
                if let Ok(meta) = meta_resp.json::<Value>().await {
                    if let Some(uri) = meta.get("jwks_uri").and_then(|v| v.as_str()) {
                        if uri != cached {
                            if let Ok(fresh) = client.get(uri).send().await {
                                if fresh.status().is_success() {
                                    return extract_keys(fresh.json::<Value>().await.ok());
                                }
                            }
                        }
                    }
                }
            }
        }

        if let Ok(jwks_resp) = jwks_resp {
            if jwks_resp.status().is_success() {
                return extract_keys(jwks_resp.json::<Value>().await.ok());
            }
        }
    }

    let Ok(meta_resp) = client.get(&meta_url).send().await else {
        return Vec::new();
    };
    if !meta_resp.status().is_success() {
        return Vec::new();
    }
    let Ok(meta) = meta_resp.json::<Value>().await else {
        return Vec::new();
    };
    let Some(uri) = meta.get("jwks_uri").and_then(|v| v.as_str()) else {
        return Vec::new();
    };
    let Ok(jwks_resp) = client.get(uri).send().await else {
        return Vec::new();
    };
    if !jwks_resp.status().is_success() {
        return Vec::new();
    }
    extract_keys(jwks_resp.json::<Value>().await.ok())
}

fn extract_keys(doc: Option<Value>) -> Vec<Value> {
    doc.and_then(|v| v.get("keys").cloned())
        .and_then(|k| k.as_array().cloned())
        .unwrap_or_default()
}

fn match_jwks_to_local(jwks_keys: &[Value], local_keys: &[LocalKey]) -> Option<ResolvedKey> {
    let mut software_match = None;

    for jwk in jwks_keys {
        if jwk.get("kty").is_none() {
            continue;
        }
        let Ok(remote_tp) = crate::backends::thumbprint_value(jwk) else {
            continue;
        };
        if let Some(match_key) = local_keys.iter().find(|k| k.thumbprint == remote_tp) {
            let kid = jwk
                .get("kid")
                .and_then(|v| v.as_str())
                .unwrap_or(&match_key.kid)
                .to_string();
            let resolved = to_resolved(match_key, &kid);
            if match_key.backend.is_hardware() {
                return Some(resolved);
            }
            if software_match.is_none() {
                software_match = Some(resolved);
            }
        }
    }

    software_match
}

fn resolve_from_config(
    config_keys: &std::collections::BTreeMap<String, LocalKeyMeta>,
    local_keys: &[LocalKey],
) -> Option<ResolvedKey> {
    let backends = discover_backends();
    let mut software_match = None;
    let mut lazy_hardware = None;

    for (kid, meta) in config_keys {
        let backend_available = backends.iter().any(|b| b.backend == meta.backend);
        if !backend_available {
            continue;
        }

        if let Some(local) = local_keys
            .iter()
            .find(|k| k.backend == meta.backend && k.key_id == meta.key_id)
        {
            let resolved = to_resolved(local, kid);
            if local.backend.is_hardware() {
                return Some(resolved);
            }
            if software_match.is_none() {
                software_match = Some(resolved);
            }
            continue;
        }

        if meta.backend.is_hardware() && lazy_hardware.is_none() {
            if let Ok(pub_jwk) = get_public_key(meta.backend, &meta.key_id) {
                if pub_jwk.get("kty").is_some() {
                    lazy_hardware = Some(ResolvedKey {
                        backend: meta.backend,
                        key_id: meta.key_id.clone(),
                        kid: kid.clone(),
                        algorithm: meta.algorithm,
                        public_jwk: pub_jwk,
                    });
                }
            }
        }
    }

    lazy_hardware.or(software_match)
}

fn to_resolved(local: &LocalKey, kid: &str) -> ResolvedKey {
    ResolvedKey {
        backend: local.backend,
        key_id: local.key_id.clone(),
        kid: kid.to_string(),
        algorithm: local.algorithm,
        public_jwk: local.public_jwk.clone(),
    }
}
