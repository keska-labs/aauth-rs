use std::collections::HashMap;
use std::sync::Arc;
use std::time::{Duration, Instant};

use http::{HeaderMap, StatusCode};

use crate::error::{AAuthError, Result};
use crate::headers::parse_aauth_requirement;
use crate::types::{Capability, Mission, PersonServerMetadata, RequirementLevel};

pub type InteractionCallback = std::sync::Arc<dyn Fn(String, String) + Send + Sync>;

pub type ClarificationCallback = std::sync::Arc<
    dyn Fn(String) -> std::pin::Pin<Box<dyn std::future::Future<Output = String> + Send>>
        + Send
        + Sync,
>;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AuthAttempt {
    AuthToken(String),
    OpaqueToken(String),
    AgentSigned,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum InjectorStep {
    Continue,
    Finish,
    ExchangeToken { resource_token: String },
    PollDeferred,
    Invalidate(AuthAttempt),
}

#[derive(Clone)]
struct CachedToken {
    auth_token: String,
    expires_at: Instant,
}

#[derive(Clone)]
struct CachedOpaque {
    token: String,
}

/// Framework-agnostic auth/caching state machine for the AAuth protocol.
///
/// Operates on `http::StatusCode` and `http::HeaderMap` only — no reqwest dependency.
/// Pair with a transport adapter (e.g. `AAuthMiddleware`) that performs signing and HTTP.
pub struct AAuthInjector {
    token_cache: HashMap<String, CachedToken>,
    opaque_cache: HashMap<String, CachedOpaque>,
    person_server_url: Option<String>,
    opaque_seed: Option<String>,
    on_opaque_token: Option<Arc<dyn Fn(String) + Send + Sync>>,
}

#[derive(Clone)]
pub struct AAuthClientOptions {
    pub provider: Arc<dyn super::keys::KeyMaterialProvider>,
    pub person_server_url: Option<String>,
    pub person_server_metadata: Option<PersonServerMetadata>,
    pub opaque_token: Option<String>,
    pub capabilities: Option<Vec<Capability>>,
    pub mission: Option<Mission>,
    pub justification: Option<String>,
    pub login_hint: Option<String>,
    pub tenant: Option<String>,
    pub domain_hint: Option<String>,
    pub prompt: Option<String>,
    pub on_metadata: Option<Arc<dyn Fn(PersonServerMetadata) + Send + Sync>>,
    pub on_auth_token: Option<Arc<dyn Fn(String, u64) + Send + Sync>>,
    pub on_opaque_token: Option<Arc<dyn Fn(String) + Send + Sync>>,
    pub on_interaction: Option<InteractionCallback>,
    pub on_clarification: Option<ClarificationCallback>,
    /// Max seconds to poll a pending URL before failing (default 300).
    pub max_poll_duration_secs: Option<u64>,
}

impl AAuthInjector {
    pub fn from_options(options: &AAuthClientOptions) -> Self {
        Self {
            token_cache: HashMap::new(),
            opaque_cache: HashMap::new(),
            person_server_url: options.person_server_url.clone(),
            opaque_seed: options.opaque_token.clone(),
            on_opaque_token: options.on_opaque_token.clone(),
        }
    }

    pub fn person_server_url(&self) -> Option<&str> {
        self.person_server_url.as_deref()
    }

    pub fn resource_origin(url: &str) -> Result<String> {
        Ok(url::Url::parse(url)
            .map_err(|e| AAuthError::Message(e.to_string()))?
            .origin()
            .ascii_serialization())
    }

    pub fn seed_opaque(&mut self, origin: &str) {
        if let Some(seed) = &self.opaque_seed {
            self.opaque_cache
                .entry(origin.to_string())
                .or_insert(CachedOpaque {
                    token: seed.clone(),
                });
        }
    }

    pub fn next_attempt(&mut self, origin: &str) -> AuthAttempt {
        if let Some(cached) = self.find_cached_token(origin) {
            return AuthAttempt::AuthToken(cached.auth_token);
        }
        if let Some(token) = self
            .opaque_cache
            .get(origin)
            .map(|entry| entry.token.clone())
        {
            return AuthAttempt::OpaqueToken(token);
        }
        AuthAttempt::AgentSigned
    }

    pub fn observe_response(
        &mut self,
        origin: &str,
        attempt: &AuthAttempt,
        status: StatusCode,
        headers: &HeaderMap,
    ) -> Result<InjectorStep> {
        if status != StatusCode::UNAUTHORIZED {
            self.cache_opaque_from_headers(origin, headers);
            if status == StatusCode::ACCEPTED {
                return Ok(InjectorStep::PollDeferred);
            }
            return Ok(InjectorStep::Finish);
        }

        match attempt {
            AuthAttempt::AuthToken(_) => {
                if let Some(cached) = self.find_cached_token_key(origin) {
                    self.token_cache.remove(&cached);
                }
                Ok(InjectorStep::Invalidate(attempt.clone()))
            }
            AuthAttempt::OpaqueToken(_) => {
                self.opaque_cache.remove(origin);
                Ok(InjectorStep::Invalidate(attempt.clone()))
            }
            AuthAttempt::AgentSigned => {
                if let Some(header) = header_value(headers, "aauth-requirement") {
                    let challenge = parse_aauth_requirement(header)?;
                    if challenge.requirement == RequirementLevel::AuthToken {
                        if let Some(resource_token) = challenge.resource_token {
                            return Ok(InjectorStep::ExchangeToken { resource_token });
                        }
                    }
                }
                Ok(InjectorStep::Finish)
            }
        }
    }

    pub fn record_auth_token(
        &mut self,
        origin: &str,
        person_server: &str,
        token: String,
        expires_in: u64,
        on_auth_token: Option<&Arc<dyn Fn(String, u64) + Send + Sync>>,
    ) {
        self.token_cache.insert(
            cache_key(origin, person_server),
            CachedToken {
                auth_token: token.clone(),
                expires_at: Instant::now() + Duration::from_secs(expires_in),
            },
        );
        if let Some(callback) = on_auth_token {
            callback(token, expires_in);
        }
    }

    fn find_cached_token(&mut self, resource_origin: &str) -> Option<CachedToken> {
        let prefix = format!("{resource_origin}|");
        let key = self
            .token_cache
            .keys()
            .find(|k| k.starts_with(&prefix))?
            .clone();
        let cached = self.token_cache.get(&key)?.clone();
        if cached.expires_at > Instant::now() + Duration::from_secs(60) {
            Some(cached)
        } else {
            self.token_cache.remove(&key);
            None
        }
    }

    fn find_cached_token_key(&self, resource_origin: &str) -> Option<String> {
        let prefix = format!("{resource_origin}|");
        self.token_cache
            .keys()
            .find(|k| k.starts_with(&prefix))
            .cloned()
    }

    fn cache_opaque_from_headers(&mut self, origin: &str, headers: &HeaderMap) {
        if let Some(token) = header_value(headers, "aauth-access") {
            self.opaque_cache.insert(
                origin.to_string(),
                CachedOpaque {
                    token: token.to_string(),
                },
            );
            if let Some(on_opaque) = &self.on_opaque_token {
                on_opaque(token.to_string());
            }
        }
    }
}

fn cache_key(resource_origin: &str, person_server: &str) -> String {
    format!("{resource_origin}|{person_server}")
}

fn header_value<'a>(headers: &'a HeaderMap, name: &str) -> Option<&'a str> {
    headers.get(name).and_then(|v| v.to_str().ok()).or_else(|| {
        headers.iter().find_map(|(k, v)| {
            if k.as_str().eq_ignore_ascii_case(name) {
                v.to_str().ok()
            } else {
                None
            }
        })
    })
}

#[cfg(test)]
mod tests {
    use std::sync::Mutex;

    use http::StatusCode;

    use super::*;

    fn headers(map: &[(&str, &str)]) -> HeaderMap {
        let mut h = HeaderMap::new();
        for (k, v) in map {
            h.insert(
                http::HeaderName::from_bytes(k.as_bytes()).unwrap(),
                http::HeaderValue::from_str(v).unwrap(),
            );
        }
        h
    }

    #[test]
    fn next_attempt_prefers_auth_over_opaque() {
        let mut inj = AAuthInjector {
            token_cache: HashMap::from([(
                "https://resource.example|https://auth.example".into(),
                CachedToken {
                    auth_token: "auth".into(),
                    expires_at: Instant::now() + Duration::from_secs(3600),
                },
            )]),
            opaque_cache: HashMap::from([(
                "https://resource.example".into(),
                CachedOpaque {
                    token: "opaque".into(),
                },
            )]),
            person_server_url: None,
            opaque_seed: None,
            on_opaque_token: None,
        };
        assert_eq!(
            inj.next_attempt("https://resource.example"),
            AuthAttempt::AuthToken("auth".into())
        );
    }

    #[test]
    fn observe_401_agent_with_challenge() {
        let inj = AAuthInjector {
            token_cache: HashMap::new(),
            opaque_cache: HashMap::new(),
            person_server_url: Some("https://person.example".into()),
            opaque_seed: None,
            on_opaque_token: None,
        };
        let mut inj = inj;
        let step = inj
            .observe_response(
                "https://resource.example",
                &AuthAttempt::AgentSigned,
                StatusCode::UNAUTHORIZED,
                &headers(&[(
                    "aauth-requirement",
                    "requirement=auth-token; resource-token=\"rt_abc\"",
                )]),
            )
            .unwrap();
        assert_eq!(
            step,
            InjectorStep::ExchangeToken {
                resource_token: "rt_abc".into()
            }
        );
    }

    #[test]
    fn observe_success_caches_opaque() {
        let captured = Arc::new(Mutex::new(None));
        let captured_cb = Arc::clone(&captured);
        let mut inj = AAuthInjector {
            token_cache: HashMap::new(),
            opaque_cache: HashMap::new(),
            person_server_url: None,
            opaque_seed: None,
            on_opaque_token: Some(Arc::new(move |t| {
                *captured_cb.lock().unwrap() = Some(t);
            })),
        };
        let step = inj
            .observe_response(
                "https://resource.example",
                &AuthAttempt::AgentSigned,
                StatusCode::OK,
                &headers(&[("aauth-access", "opaque_tok")]),
            )
            .unwrap();
        assert_eq!(step, InjectorStep::Finish);
        assert_eq!(
            inj.opaque_cache
                .get("https://resource.example")
                .map(|e| e.token.as_str()),
            Some("opaque_tok")
        );
        assert_eq!(captured.lock().unwrap().as_deref(), Some("opaque_tok"));
    }
}
