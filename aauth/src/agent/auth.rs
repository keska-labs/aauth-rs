use std::collections::HashMap;
use std::sync::Arc;
use std::time::{Duration, Instant};

use http::{HeaderMap, StatusCode};

use crate::error::Result;
use crate::http_util::header_value;
#[cfg(feature = "resource-verify")]
use crate::metadata::MetadataFetcher;
use crate::protocol::AAuthChallenge;
use crate::protocol::{AAUTH_ACCESS, AAUTH_REQUIREMENT, Capability, Mission, PersonServerMetadata};

pub type InteractionCallback = std::sync::Arc<dyn Fn(String, String) + Send + Sync>;

pub type ClarificationCallback = std::sync::Arc<
    dyn Fn(String) -> std::pin::Pin<Box<dyn std::future::Future<Output = String> + Send>>
        + Send
        + Sync,
>;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AgentAuthAttempt {
    AuthToken(String),
    OpaqueToken(String),
    AgentSigned,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AgentAuthStep {
    Finish,
    ExchangeToken { resource_token: String },
    PollDeferred,
    Invalidate(AgentAuthAttempt),
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
/// Pair with a transport adapter (e.g. `aauth_reqwest::AgentMiddleware`) that performs
/// signing and HTTP.
pub struct AgentAuth {
    token_cache: HashMap<String, CachedToken>,
    opaque_cache: HashMap<String, CachedOpaque>,
    person_server_url: Option<String>,
    opaque_seed: Option<String>,
    on_opaque_token: Option<Arc<dyn Fn(String) + Send + Sync>>,
}

/// Configuration for an AAuth agent client (signing, token exchange, deferred flows).
#[derive(Clone)]
pub struct AgentOptions {
    pub(crate) provider: Arc<dyn super::keys::KeyMaterialProvider>,
    pub(crate) person_server_url: Option<String>,
    pub(crate) person_server_metadata: Option<PersonServerMetadata>,
    pub(crate) opaque_token: Option<String>,
    pub(crate) capabilities: Option<Vec<Capability>>,
    pub(crate) mission: Option<Mission>,
    pub(crate) justification: Option<String>,
    pub(crate) login_hint: Option<String>,
    pub(crate) tenant: Option<String>,
    pub(crate) domain_hint: Option<String>,
    pub(crate) prompt: Option<String>,
    pub(crate) on_metadata: Option<Arc<dyn Fn(PersonServerMetadata) + Send + Sync>>,
    pub(crate) on_auth_token: Option<Arc<dyn Fn(String, u64) + Send + Sync>>,
    pub(crate) on_opaque_token: Option<Arc<dyn Fn(String) + Send + Sync>>,
    pub(crate) on_interaction: Option<InteractionCallback>,
    pub(crate) on_clarification: Option<ClarificationCallback>,
    /// Max seconds to poll a pending URL before failing (default 300).
    pub(crate) max_poll_duration_secs: Option<u64>,
    /// When set (requires `resource-verify`; enable via `aauth-reqwest`'s `verify` feature),
    /// resource and auth tokens are verified before use.
    #[cfg(feature = "resource-verify")]
    pub(crate) metadata_fetcher: Option<Arc<dyn MetadataFetcher>>,
}

/// Builder for [`AgentOptions`]. Only `provider` is required.
#[derive(Clone)]
pub struct AgentOptionsBuilder {
    provider: Arc<dyn super::keys::KeyMaterialProvider>,
    person_server_url: Option<String>,
    person_server_metadata: Option<PersonServerMetadata>,
    opaque_token: Option<String>,
    capabilities: Option<Vec<Capability>>,
    mission: Option<Mission>,
    justification: Option<String>,
    login_hint: Option<String>,
    tenant: Option<String>,
    domain_hint: Option<String>,
    prompt: Option<String>,
    on_metadata: Option<Arc<dyn Fn(PersonServerMetadata) + Send + Sync>>,
    on_auth_token: Option<Arc<dyn Fn(String, u64) + Send + Sync>>,
    on_opaque_token: Option<Arc<dyn Fn(String) + Send + Sync>>,
    on_interaction: Option<InteractionCallback>,
    on_clarification: Option<ClarificationCallback>,
    max_poll_duration_secs: Option<u64>,
    #[cfg(feature = "resource-verify")]
    metadata_fetcher: Option<Arc<dyn MetadataFetcher>>,
}

impl AgentOptions {
    pub fn builder(provider: Arc<dyn super::keys::KeyMaterialProvider>) -> AgentOptionsBuilder {
        AgentOptionsBuilder::new(provider)
    }

    pub fn provider(&self) -> &Arc<dyn super::keys::KeyMaterialProvider> {
        &self.provider
    }

    pub fn person_server_url(&self) -> Option<&str> {
        self.person_server_url.as_deref()
    }

    pub fn person_server_metadata(&self) -> Option<&PersonServerMetadata> {
        self.person_server_metadata.as_ref()
    }

    pub fn opaque_token(&self) -> Option<&str> {
        self.opaque_token.as_deref()
    }

    pub fn capabilities(&self) -> Option<&Vec<Capability>> {
        self.capabilities.as_ref()
    }

    pub fn mission(&self) -> Option<&Mission> {
        self.mission.as_ref()
    }

    pub fn justification(&self) -> Option<&str> {
        self.justification.as_deref()
    }

    pub fn login_hint(&self) -> Option<&str> {
        self.login_hint.as_deref()
    }

    pub fn tenant(&self) -> Option<&str> {
        self.tenant.as_deref()
    }

    pub fn domain_hint(&self) -> Option<&str> {
        self.domain_hint.as_deref()
    }

    pub fn prompt(&self) -> Option<&str> {
        self.prompt.as_deref()
    }

    pub fn on_metadata(&self) -> Option<&Arc<dyn Fn(PersonServerMetadata) + Send + Sync>> {
        self.on_metadata.as_ref()
    }

    pub fn on_auth_token(&self) -> Option<&Arc<dyn Fn(String, u64) + Send + Sync>> {
        self.on_auth_token.as_ref()
    }

    pub fn on_opaque_token(&self) -> Option<&Arc<dyn Fn(String) + Send + Sync>> {
        self.on_opaque_token.as_ref()
    }

    pub fn on_interaction(&self) -> Option<&InteractionCallback> {
        self.on_interaction.as_ref()
    }

    pub fn on_clarification(&self) -> Option<&ClarificationCallback> {
        self.on_clarification.as_ref()
    }

    pub fn max_poll_duration_secs(&self) -> Option<u64> {
        self.max_poll_duration_secs
    }

    #[cfg(feature = "resource-verify")]
    pub fn metadata_fetcher(&self) -> Option<&Arc<dyn MetadataFetcher>> {
        self.metadata_fetcher.as_ref()
    }
}

impl AgentOptionsBuilder {
    pub fn new(provider: Arc<dyn super::keys::KeyMaterialProvider>) -> Self {
        Self {
            provider,
            person_server_url: None,
            person_server_metadata: None,
            opaque_token: None,
            capabilities: None,
            mission: None,
            justification: None,
            login_hint: None,
            tenant: None,
            domain_hint: None,
            prompt: None,
            on_metadata: None,
            on_auth_token: None,
            on_opaque_token: None,
            on_interaction: None,
            on_clarification: None,
            max_poll_duration_secs: None,
            #[cfg(feature = "resource-verify")]
            metadata_fetcher: None,
        }
    }

    pub fn person_server_url(mut self, url: impl Into<String>) -> Self {
        self.person_server_url = Some(url.into());
        self
    }

    pub fn person_server_metadata(mut self, metadata: PersonServerMetadata) -> Self {
        self.person_server_metadata = Some(metadata);
        self
    }

    pub fn opaque_token(mut self, token: impl Into<String>) -> Self {
        self.opaque_token = Some(token.into());
        self
    }

    pub fn capabilities(mut self, capabilities: Vec<Capability>) -> Self {
        self.capabilities = Some(capabilities);
        self
    }

    pub fn mission(mut self, mission: Mission) -> Self {
        self.mission = Some(mission);
        self
    }

    pub fn justification(mut self, justification: impl Into<String>) -> Self {
        self.justification = Some(justification.into());
        self
    }

    pub fn login_hint(mut self, login_hint: impl Into<String>) -> Self {
        self.login_hint = Some(login_hint.into());
        self
    }

    pub fn tenant(mut self, tenant: impl Into<String>) -> Self {
        self.tenant = Some(tenant.into());
        self
    }

    pub fn domain_hint(mut self, domain_hint: impl Into<String>) -> Self {
        self.domain_hint = Some(domain_hint.into());
        self
    }

    pub fn prompt(mut self, prompt: impl Into<String>) -> Self {
        self.prompt = Some(prompt.into());
        self
    }

    pub fn on_metadata(
        mut self,
        callback: Arc<dyn Fn(PersonServerMetadata) + Send + Sync>,
    ) -> Self {
        self.on_metadata = Some(callback);
        self
    }

    pub fn on_auth_token(mut self, callback: Arc<dyn Fn(String, u64) + Send + Sync>) -> Self {
        self.on_auth_token = Some(callback);
        self
    }

    pub fn on_opaque_token(mut self, callback: Arc<dyn Fn(String) + Send + Sync>) -> Self {
        self.on_opaque_token = Some(callback);
        self
    }

    pub fn on_interaction(mut self, callback: InteractionCallback) -> Self {
        self.on_interaction = Some(callback);
        self
    }

    pub fn on_clarification(mut self, callback: ClarificationCallback) -> Self {
        self.on_clarification = Some(callback);
        self
    }

    pub fn max_poll_duration_secs(mut self, secs: u64) -> Self {
        self.max_poll_duration_secs = Some(secs);
        self
    }

    #[cfg(feature = "resource-verify")]
    pub fn metadata_fetcher(mut self, fetcher: Arc<dyn MetadataFetcher>) -> Self {
        self.metadata_fetcher = Some(fetcher);
        self
    }

    pub fn build(self) -> AgentOptions {
        AgentOptions {
            provider: self.provider,
            person_server_url: self.person_server_url,
            person_server_metadata: self.person_server_metadata,
            opaque_token: self.opaque_token,
            capabilities: self.capabilities,
            mission: self.mission,
            justification: self.justification,
            login_hint: self.login_hint,
            tenant: self.tenant,
            domain_hint: self.domain_hint,
            prompt: self.prompt,
            on_metadata: self.on_metadata,
            on_auth_token: self.on_auth_token,
            on_opaque_token: self.on_opaque_token,
            on_interaction: self.on_interaction,
            on_clarification: self.on_clarification,
            max_poll_duration_secs: self.max_poll_duration_secs,
            #[cfg(feature = "resource-verify")]
            metadata_fetcher: self.metadata_fetcher,
        }
    }
}

impl AgentAuth {
    pub fn from_options(options: &AgentOptions) -> Self {
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
            .map_err(crate::error::AgentAuthError::InvalidOrigin)?
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

    pub fn next_attempt(&mut self, origin: &str) -> AgentAuthAttempt {
        if let Some(cached) = self.find_cached_token(origin) {
            return AgentAuthAttempt::AuthToken(cached.auth_token);
        }
        if let Some(token) = self
            .opaque_cache
            .get(origin)
            .map(|entry| entry.token.clone())
        {
            return AgentAuthAttempt::OpaqueToken(token);
        }
        AgentAuthAttempt::AgentSigned
    }

    pub fn observe_response(
        &mut self,
        origin: &str,
        attempt: &AgentAuthAttempt,
        status: StatusCode,
        headers: &HeaderMap,
    ) -> Result<AgentAuthStep> {
        if status != StatusCode::UNAUTHORIZED {
            self.cache_opaque_from_headers(origin, headers);
            if status == StatusCode::ACCEPTED {
                return Ok(AgentAuthStep::PollDeferred);
            }
            return Ok(AgentAuthStep::Finish);
        }

        match attempt {
            AgentAuthAttempt::AuthToken(_) => {
                if let Some(cached) = self.find_cached_token_key(origin) {
                    self.token_cache.remove(&cached);
                }
                Ok(AgentAuthStep::Invalidate(attempt.clone()))
            }
            AgentAuthAttempt::OpaqueToken(_) => {
                self.opaque_cache.remove(origin);
                Ok(AgentAuthStep::Invalidate(attempt.clone()))
            }
            AgentAuthAttempt::AgentSigned => {
                if let Some(header) = header_value(headers, &AAUTH_REQUIREMENT) {
                    let challenge = AAuthChallenge::from_header(header)?;
                    if let crate::protocol::AAuthChallenge::AuthToken { resource_token } = challenge
                    {
                        return Ok(AgentAuthStep::ExchangeToken { resource_token });
                    }
                }
                Ok(AgentAuthStep::Finish)
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
            format!("{origin}|{person_server}"),
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
        if let Some(token) = header_value(headers, &AAUTH_ACCESS) {
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

#[cfg(test)]
mod tests {
    use std::sync::Mutex;

    use http::StatusCode;

    use crate::protocol::{AAUTH_ACCESS_NAME, AAUTH_REQUIREMENT_NAME};

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
        let mut inj = AgentAuth {
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
            AgentAuthAttempt::AuthToken("auth".into())
        );
    }

    #[test]
    fn observe_401_agent_with_challenge() {
        let inj = AgentAuth {
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
                &AgentAuthAttempt::AgentSigned,
                StatusCode::UNAUTHORIZED,
                &headers(&[(
                    AAUTH_REQUIREMENT_NAME,
                    "requirement=auth-token; resource-token=\"rt_abc\"",
                )]),
            )
            .unwrap();
        assert_eq!(
            step,
            AgentAuthStep::ExchangeToken {
                resource_token: "rt_abc".into()
            }
        );
    }

    #[test]
    fn observe_success_caches_opaque() {
        let captured = Arc::new(Mutex::new(None));
        let captured_cb = Arc::clone(&captured);
        let mut inj = AgentAuth {
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
                &AgentAuthAttempt::AgentSigned,
                StatusCode::OK,
                &headers(&[(AAUTH_ACCESS_NAME, "opaque_tok")]),
            )
            .unwrap();
        assert_eq!(step, AgentAuthStep::Finish);
        assert_eq!(
            inj.opaque_cache
                .get("https://resource.example")
                .map(|e| e.token.as_str()),
            Some("opaque_tok")
        );
        assert_eq!(captured.lock().unwrap().as_deref(), Some("opaque_tok"));
    }
}
