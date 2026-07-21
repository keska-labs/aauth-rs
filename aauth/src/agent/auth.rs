use std::collections::{HashMap, HashSet};
use std::sync::Arc;
use std::time::{Duration, Instant};

use http::{HeaderMap, StatusCode};

use crate::agent::keys::KeyMaterialProvider;
use crate::error::Result;
use crate::http_util::header_value;
use crate::metadata::AbsentMetadataFetcher;
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
    /// Cached opaque from this response; retry the original request with it.
    ///
    /// Spec: `#fig-resource-managed`, `#aauth-access`
    RetryWithOpaque,
    ExchangeToken {
        resource_token: String,
    },
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

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
struct AuthTokenCacheKey {
    origin: String,
    person_server: String,
}

/// Framework-agnostic auth/caching state machine for the AAuth protocol.
///
/// Operates on `http::StatusCode` and `http::HeaderMap` only — no reqwest dependency.
/// Pair with a transport adapter (e.g. `aauth_reqwest::AgentMiddleware`) that performs
/// signing and HTTP.
pub struct AgentAuth {
    token_cache: HashMap<AuthTokenCacheKey, CachedToken>,
    opaque_cache: HashMap<String, CachedOpaque>,
    /// Origins for which we already attempted proactive `authorization_endpoint`.
    authorize_tried: HashSet<String>,
    person_server_url: Option<String>,
    opaque_seed: Option<String>,
    on_opaque_token: Option<Arc<dyn Fn(String) + Send + Sync>>,
}

/// Configuration for an AAuth agent client (signing, token exchange, deferred flows).
#[derive(Clone)]
pub struct AgentOptions<P, F = AbsentMetadataFetcher>
where
    P: KeyMaterialProvider + Clone,
    F: MetadataFetcher + Clone,
{
    pub(crate) provider: P,
    pub(crate) person_server_url: Option<String>,
    pub(crate) person_server_metadata: Option<PersonServerMetadata>,
    pub(crate) opaque_token: Option<String>,
    pub(crate) scope: Option<String>,
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
    /// JWKS / well-known discovery for verifying resource challenges and auth tokens.
    pub(crate) metadata_fetcher: F,
    /// When `true` (default), verify the auth token JWT signature via the issuer JWKS
    /// (spec SHOULD). Resource-challenge verification and auth-token claim binding always run.
    pub(crate) verify_auth_signature: bool,
}

/// Builder for [`AgentOptions`]. Only `provider` is required.
#[derive(Clone)]
pub struct AgentOptionsBuilder<P, F = AbsentMetadataFetcher>
where
    P: KeyMaterialProvider + Clone,
    F: MetadataFetcher + Clone,
{
    provider: P,
    person_server_url: Option<String>,
    person_server_metadata: Option<PersonServerMetadata>,
    opaque_token: Option<String>,
    scope: Option<String>,
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
    metadata_fetcher: F,
    verify_auth_signature: bool,
}

impl<P> AgentOptions<P, AbsentMetadataFetcher>
where
    P: KeyMaterialProvider + Clone,
{
    pub fn builder(provider: P) -> AgentOptionsBuilder<P, AbsentMetadataFetcher> {
        AgentOptionsBuilder::new(provider)
    }
}

impl<P, F> AgentOptions<P, F>
where
    P: KeyMaterialProvider + Clone,
    F: MetadataFetcher + Clone,
{
    pub fn provider(&self) -> &P {
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

    /// Scope string for proactive `authorization_endpoint` requests.
    pub fn scope(&self) -> Option<&str> {
        self.scope.as_deref()
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

    pub fn metadata_fetcher(&self) -> &F {
        &self.metadata_fetcher
    }

    pub fn verify_auth_signature(&self) -> bool {
        self.verify_auth_signature
    }
}

impl<P> AgentOptionsBuilder<P, AbsentMetadataFetcher>
where
    P: KeyMaterialProvider + Clone,
{
    pub fn new(provider: P) -> Self {
        Self {
            provider,
            person_server_url: None,
            person_server_metadata: None,
            opaque_token: None,
            scope: None,
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
            metadata_fetcher: AbsentMetadataFetcher,
            verify_auth_signature: true,
        }
    }
}

impl<P, F> AgentOptionsBuilder<P, F>
where
    P: KeyMaterialProvider + Clone,
    F: MetadataFetcher + Clone,
{
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

    /// Scope for resource `authorization_endpoint` POST body (`AuthorizationRequest.scope`).
    pub fn scope(mut self, scope: impl Into<String>) -> Self {
        self.scope = Some(scope.into());
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

    /// Enable or disable auth-token JWT signature verification (spec SHOULD; default `true`).
    /// Resource-challenge verification and auth-token claim checks always run.
    pub fn verify_auth_signature(mut self, enabled: bool) -> Self {
        self.verify_auth_signature = enabled;
        self
    }

    /// Set the metadata fetcher, changing the builder's `F` type parameter.
    pub fn metadata_fetcher<F2: MetadataFetcher + Clone>(
        self,
        fetcher: F2,
    ) -> AgentOptionsBuilder<P, F2> {
        AgentOptionsBuilder {
            provider: self.provider,
            person_server_url: self.person_server_url,
            person_server_metadata: self.person_server_metadata,
            opaque_token: self.opaque_token,
            scope: self.scope,
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
            metadata_fetcher: fetcher,
            verify_auth_signature: self.verify_auth_signature,
        }
    }

    pub fn build(self) -> AgentOptions<P, F>
    where
        F: Clone,
    {
        AgentOptions {
            provider: self.provider,
            person_server_url: self.person_server_url,
            person_server_metadata: self.person_server_metadata,
            opaque_token: self.opaque_token,
            scope: self.scope,
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
            metadata_fetcher: self.metadata_fetcher,
            verify_auth_signature: self.verify_auth_signature,
        }
    }
}

impl AgentAuth {
    pub fn from_options<P, F>(options: &AgentOptions<P, F>) -> Self
    where
        P: KeyMaterialProvider + Clone,
        F: MetadataFetcher + Clone,
    {
        Self {
            token_cache: HashMap::new(),
            opaque_cache: HashMap::new(),
            authorize_tried: HashSet::new(),
            person_server_url: options.person_server_url.clone(),
            opaque_seed: options.opaque_token.clone(),
            on_opaque_token: options.on_opaque_token.clone(),
        }
    }

    pub fn person_server_url(&self) -> Option<&str> {
        self.person_server_url.as_deref()
    }

    /// Mark that proactive authorize was attempted; returns `true` if this is the first try
    /// and no opaque token is cached yet.
    pub fn begin_authorize_attempt(&mut self, origin: &str) -> bool {
        if self.opaque_cache.contains_key(origin) {
            return false;
        }
        self.authorize_tried.insert(origin.to_string())
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
        // Spec: `#deferred-responses` — agents MUST handle `202` by polling Location.
        if status != StatusCode::UNAUTHORIZED {
            let cached_opaque = self.cache_opaque_from_headers(origin, headers);
            if status == StatusCode::ACCEPTED {
                return Ok(AgentAuthStep::PollDeferred);
            }
            // Spec: `#fig-resource-managed`, `#aauth-access` — immediate opaque grant
            // on an agent-signed attempt means retry with Authorization: AAuth.
            if cached_opaque && matches!(attempt, AgentAuthAttempt::AgentSigned) {
                return Ok(AgentAuthStep::RetryWithOpaque);
            }
            return Ok(AgentAuthStep::Finish);
        }

        match attempt {
            // Spec: `#re-authorization`, `#requirement-auth-token` (step-up) —
            // drop cached auth and retry; step-up currently does not consume a
            // new resource-token from this 401 (invalidate → agent-signed → challenge).
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
                // Spec: `#requirement-auth-token`, `#resource-challenge-verification`,
                // `#requirement-agent-token`
                if let Some(header) = header_value(headers, &AAUTH_REQUIREMENT) {
                    let challenge = AAuthChallenge::from_header(header)?;
                    match challenge {
                        crate::protocol::AAuthChallenge::AuthToken { resource_token } => {
                            return Ok(AgentAuthStep::ExchangeToken { resource_token });
                        }
                        // Already presenting an agent JWT; challenge is for
                        // non-AAuth clients. Surface the 401.
                        crate::protocol::AAuthChallenge::AgentToken => {
                            return Ok(AgentAuthStep::Finish);
                        }
                        _ => {}
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
            AuthTokenCacheKey {
                origin: origin.to_string(),
                person_server: person_server.to_string(),
            },
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
        let key = self.find_cached_token_key(resource_origin)?;
        let cached = self.token_cache.get(&key)?.clone();
        if cached.expires_at > Instant::now() + Duration::from_secs(60) {
            Some(cached)
        } else {
            self.token_cache.remove(&key);
            None
        }
    }

    fn find_cached_token_key(&self, resource_origin: &str) -> Option<AuthTokenCacheKey> {
        self.token_cache
            .keys()
            .find(|k| k.origin == resource_origin)
            .cloned()
    }

    fn cache_opaque_from_headers(&mut self, origin: &str, headers: &HeaderMap) -> bool {
        let mut values = headers.get_all(AAUTH_ACCESS).iter();
        let Some(raw) = values.next().and_then(|v| v.to_str().ok()) else {
            return false;
        };
        if values.next().is_some() {
            return false;
        }
        let Ok(token) = crate::protocol::parse_aauth_access_header(raw) else {
            return false;
        };
        let changed = self
            .opaque_cache
            .get(origin)
            .is_none_or(|e| e.token != token);
        if changed {
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
        changed
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
                AuthTokenCacheKey {
                    origin: "https://resource.example".into(),
                    person_server: "https://auth.example".into(),
                },
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
            authorize_tried: HashSet::new(),
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
            authorize_tried: HashSet::new(),
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
            authorize_tried: HashSet::new(),
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
        assert_eq!(step, AgentAuthStep::RetryWithOpaque);
        assert_eq!(
            inj.opaque_cache
                .get("https://resource.example")
                .map(|e| e.token.as_str()),
            Some("opaque_tok")
        );
        assert_eq!(captured.lock().unwrap().as_deref(), Some("opaque_tok"));
    }

    #[test]
    fn observe_opaque_retry_finishes_on_rolling_refresh() {
        let mut inj = AgentAuth {
            token_cache: HashMap::new(),
            opaque_cache: HashMap::from([(
                "https://resource.example".into(),
                CachedOpaque {
                    token: "old_tok".into(),
                },
            )]),
            authorize_tried: HashSet::new(),
            person_server_url: None,
            opaque_seed: None,
            on_opaque_token: None,
        };
        let step = inj
            .observe_response(
                "https://resource.example",
                &AgentAuthAttempt::OpaqueToken("old_tok".into()),
                StatusCode::OK,
                &headers(&[(AAUTH_ACCESS_NAME, "new_tok")]),
            )
            .unwrap();
        assert_eq!(step, AgentAuthStep::Finish);
        assert_eq!(
            inj.opaque_cache
                .get("https://resource.example")
                .map(|e| e.token.as_str()),
            Some("new_tok")
        );
    }

    #[test]
    fn observe_ignores_invalid_aauth_access() {
        let mut inj = AgentAuth {
            token_cache: HashMap::new(),
            opaque_cache: HashMap::new(),
            authorize_tried: HashSet::new(),
            person_server_url: None,
            opaque_seed: None,
            on_opaque_token: None,
        };
        let step = inj
            .observe_response(
                "https://resource.example",
                &AgentAuthAttempt::AgentSigned,
                StatusCode::OK,
                &headers(&[(AAUTH_ACCESS_NAME, "bad token")]),
            )
            .unwrap();
        assert_eq!(step, AgentAuthStep::Finish);
        assert!(inj.opaque_cache.is_empty());
    }
}
