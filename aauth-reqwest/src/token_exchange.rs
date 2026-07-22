use std::future::Future;
use std::sync::Arc;

use aauth::DeferredError;
use aauth::MetadataError;
use aauth::agent::auth::{AgentOptions, ClarificationCallback, InteractionCallback};
use aauth::protocol::{
    AAUTH_REQUIREMENT, AAuthChallenge, AAuthProtocolError, Capability, PREFER,
    PersonServerMetadata, TokenExchangeRequest, TokenResponseBody,
};
use http::header::{CONTENT_TYPE, LOCATION};
use http::{Method, Request as HttpRequest};
use reqwest::{Request, Response};

use crate::deferred::{AgentDeferredOptions, poll_deferred_with};
use crate::error::Result;
use crate::signed::SignedSend;

const PREFER_WAIT: u64 = 45;

#[derive(Debug, Clone)]
pub struct TokenExchangeResult {
    pub auth_token: String,
    pub expires_in: u64,
}

#[derive(Clone)]
pub struct TokenExchangeOptions {
    pub(crate) person_server_url: String,
    pub(crate) person_server_metadata: Option<PersonServerMetadata>,
    pub(crate) on_metadata: Option<Arc<dyn Fn(PersonServerMetadata) + Send + Sync>>,
    pub(crate) resource_token: String,
    pub(crate) justification: Option<String>,
    pub(crate) login_hint: Option<String>,
    pub(crate) tenant: Option<String>,
    pub(crate) domain_hint: Option<String>,
    pub(crate) capabilities: Option<Vec<Capability>>,
    pub(crate) prompt: Option<String>,
    pub(crate) on_interaction: Option<InteractionCallback>,
    pub(crate) on_clarification: Option<ClarificationCallback>,
    pub(crate) max_poll_duration_secs: Option<u64>,
}

#[derive(Clone)]
pub struct TokenExchangeOptionsBuilder {
    person_server_url: String,
    resource_token: String,
    person_server_metadata: Option<PersonServerMetadata>,
    on_metadata: Option<Arc<dyn Fn(PersonServerMetadata) + Send + Sync>>,
    justification: Option<String>,
    login_hint: Option<String>,
    tenant: Option<String>,
    domain_hint: Option<String>,
    capabilities: Option<Vec<Capability>>,
    prompt: Option<String>,
    on_interaction: Option<InteractionCallback>,
    on_clarification: Option<ClarificationCallback>,
    max_poll_duration_secs: Option<u64>,
}

impl TokenExchangeOptions {
    pub fn builder(
        person_server_url: impl Into<String>,
        resource_token: impl Into<String>,
    ) -> TokenExchangeOptionsBuilder {
        TokenExchangeOptionsBuilder::new(person_server_url, resource_token)
    }

    /// Build exchange options from shared [`AgentOptions`] fields.
    pub(crate) fn from_agent_options<P, F>(
        options: &AgentOptions<P, F>,
        person_server_url: String,
        resource_token: String,
    ) -> Self
    where
        P: aauth::KeyMaterialProvider + Clone,
        F: aauth::MetadataFetcher + Clone,
    {
        let mut builder = Self::builder(person_server_url, resource_token);
        if let Some(metadata) = options.person_server_metadata().cloned() {
            builder = builder.person_server_metadata(metadata);
        }
        if let Some(on_metadata) = options.on_metadata().cloned() {
            builder = builder.on_metadata(on_metadata);
        }
        if let Some(justification) = options.justification().map(str::to_string) {
            builder = builder.justification(justification);
        }
        if let Some(login_hint) = options.login_hint().map(str::to_string) {
            builder = builder.login_hint(login_hint);
        }
        if let Some(tenant) = options.tenant().map(str::to_string) {
            builder = builder.tenant(tenant);
        }
        if let Some(domain_hint) = options.domain_hint().map(str::to_string) {
            builder = builder.domain_hint(domain_hint);
        }
        if let Some(caps) = options.capabilities().cloned() {
            builder = builder.capabilities(caps);
        }
        if let Some(prompt) = options.prompt().map(str::to_string) {
            builder = builder.prompt(prompt);
        }
        if let Some(on_interaction) = options.on_interaction().cloned() {
            builder = builder.on_interaction(on_interaction);
        }
        if let Some(on_clarification) = options.on_clarification().cloned() {
            builder = builder.on_clarification(on_clarification);
        }
        if let Some(secs) = options.max_poll_duration_secs() {
            builder = builder.max_poll_duration_secs(secs);
        }
        builder.build()
    }
}

impl TokenExchangeOptionsBuilder {
    pub fn new(person_server_url: impl Into<String>, resource_token: impl Into<String>) -> Self {
        Self {
            person_server_url: person_server_url.into(),
            resource_token: resource_token.into(),
            person_server_metadata: None,
            on_metadata: None,
            justification: None,
            login_hint: None,
            tenant: None,
            domain_hint: None,
            capabilities: None,
            prompt: None,
            on_interaction: None,
            on_clarification: None,
            max_poll_duration_secs: None,
        }
    }

    pub fn person_server_metadata(mut self, metadata: PersonServerMetadata) -> Self {
        self.person_server_metadata = Some(metadata);
        self
    }

    pub fn on_metadata(
        mut self,
        callback: Arc<dyn Fn(PersonServerMetadata) + Send + Sync>,
    ) -> Self {
        self.on_metadata = Some(callback);
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

    pub fn capabilities(mut self, capabilities: Vec<Capability>) -> Self {
        self.capabilities = Some(capabilities);
        self
    }

    pub fn prompt(mut self, prompt: impl Into<String>) -> Self {
        self.prompt = Some(prompt.into());
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

    pub fn build(self) -> TokenExchangeOptions {
        TokenExchangeOptions {
            person_server_url: self.person_server_url,
            resource_token: self.resource_token,
            person_server_metadata: self.person_server_metadata,
            on_metadata: self.on_metadata,
            justification: self.justification,
            login_hint: self.login_hint,
            tenant: self.tenant,
            domain_hint: self.domain_hint,
            capabilities: self.capabilities,
            prompt: self.prompt,
            on_interaction: self.on_interaction,
            on_clarification: self.on_clarification,
            max_poll_duration_secs: self.max_poll_duration_secs,
        }
    }
}

#[derive(Debug, Clone)]
pub struct TokenExchangeError {
    pub status: u16,
    pub aauth_error: Option<AAuthProtocolError>,
}

impl std::fmt::Display for TokenExchangeError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        if let Some(err) = &self.aauth_error {
            write!(
                f,
                "{}",
                err.error_description
                    .as_deref()
                    .unwrap_or(err.error.as_str())
            )
        } else {
            write!(f, "Token exchange failed with status {}", self.status)
        }
    }
}

impl std::error::Error for TokenExchangeError {}

pub async fn exchange_token<F, Fut>(
    options: TokenExchangeOptions,
    send: F,
) -> Result<TokenExchangeResult>
where
    F: FnMut(Request) -> Fut + Send,
    Fut: Future<Output = Result<Response>> + Send,
{
    struct Adapter<F>(F);

    impl<F, Fut> SignedSend for Adapter<F>
    where
        F: FnMut(Request) -> Fut + Send,
        Fut: Future<Output = Result<Response>> + Send,
    {
        async fn send(&mut self, req: Request) -> Result<Response> {
            (self.0)(req).await
        }
    }

    exchange_token_with(options, &mut Adapter(send)).await
}

pub(crate) async fn exchange_token_with<S: SignedSend>(
    options: TokenExchangeOptions,
    send: &mut S,
) -> Result<TokenExchangeResult> {
    let metadata = if let Some(metadata) = options.person_server_metadata.clone() {
        metadata
    } else {
        let metadata = fetch_metadata(&options.person_server_url, send).await?;
        if let Some(on_metadata) = &options.on_metadata {
            on_metadata(metadata.clone());
        }
        metadata
    };

    let body = TokenExchangeRequest {
        resource_token: options.resource_token,
        upstream_token: None,
        subagent_token: None,
        justification: options.justification,
        login_hint: options.login_hint,
        tenant: options.tenant,
        domain_hint: options.domain_hint,
        capabilities: options.capabilities,
        prompt: options.prompt,
        platform: None,
        device: None,
    };

    let token_body = serde_json::to_string(&body).map_err(DeferredError::Serialize)?;

    let http_req = HttpRequest::builder()
        .method(Method::POST)
        .uri(&metadata.token_endpoint)
        .header(CONTENT_TYPE, "application/json")
        .header(PREFER, format!("wait={PREFER_WAIT}"))
        .body(token_body.into_bytes())
        .expect("valid http request");
    let response = send
        .send(Request::try_from(http_req).expect("valid reqwest request"))
        .await?;

    if response.status().as_u16() == 202 {
        let location = response
            .headers()
            .get(LOCATION)
            .and_then(|v| v.to_str().ok())
            .ok_or(DeferredError::MissingLocation)?
            .to_string();

        let mut deferred =
            AgentDeferredOptions::builder(resolve_url(&options.person_server_url, &location));
        if let Some(header) = response
            .headers()
            .get(AAUTH_REQUIREMENT)
            .and_then(|v| v.to_str().ok())
            && let Ok(AAuthChallenge::Interaction { url, code }) =
                AAuthChallenge::from_header(header)
        {
            deferred = deferred.interaction(url, code);
        }
        if let Some(cb) = options.on_interaction {
            deferred = deferred.on_interaction(cb);
        }
        if let Some(cb) = options.on_clarification {
            deferred = deferred.on_clarification(cb);
        }
        if let Some(secs) = options.max_poll_duration_secs {
            deferred = deferred.max_poll_duration_secs(secs);
        }

        let result = poll_deferred_with(deferred.build(), send).await?;

        if result.response.status().is_success() {
            let url = result.response.url().to_string();
            let bytes = result
                .response
                .bytes()
                .await
                .map_err(|e| MetadataError::Request {
                    url: url.clone(),
                    source: Box::new(e),
                })?;
            let parsed: TokenResponseBody = serde_json::from_slice(&bytes)
                .map_err(|e| MetadataError::Decode { url, source: e })?;
            return Ok(TokenExchangeResult {
                auth_token: parsed.auth_token,
                expires_in: parsed.expires_in,
            });
        }

        return Err(TokenExchangeError {
            status: result.response.status().as_u16(),
            aauth_error: result.error,
        }
        .into());
    }

    if response.status().is_success() {
        let url = response.url().to_string();
        let bytes = response.bytes().await.map_err(|e| MetadataError::Request {
            url: url.clone(),
            source: Box::new(e),
        })?;
        let parsed: TokenResponseBody =
            serde_json::from_slice(&bytes).map_err(|e| MetadataError::Decode { url, source: e })?;
        return Ok(TokenExchangeResult {
            auth_token: parsed.auth_token,
            expires_in: parsed.expires_in,
        });
    }

    let status = response.status().as_u16();
    let aauth_error = parse_protocol_error(response).await;
    Err(TokenExchangeError {
        status,
        aauth_error,
    }
    .into())
}

async fn parse_protocol_error(response: Response) -> Option<AAuthProtocolError> {
    if !headers_contain_json(response.headers()) {
        return None;
    }
    response.json().await.ok()
}

fn headers_contain_json(headers: &http::HeaderMap) -> bool {
    headers
        .get(CONTENT_TYPE)
        .and_then(|v| v.to_str().ok())
        .is_some_and(|v| v.contains("application/json"))
}

async fn fetch_metadata<S: SignedSend>(
    person_server_url: &str,
    send: &mut S,
) -> Result<PersonServerMetadata> {
    let metadata_url = format!(
        "{}/.well-known/aauth-person.json",
        person_server_url.trim_end_matches('/')
    );
    let http_req = HttpRequest::builder()
        .method(Method::GET)
        .uri(&metadata_url)
        .body(Vec::new())
        .expect("valid http request");
    let response = send
        .send(Request::try_from(http_req).expect("valid reqwest request"))
        .await?;

    if !response.status().is_success() {
        return Err(MetadataError::HttpStatus {
            url: metadata_url,
            status: response.status().as_u16(),
        }
        .into());
    }

    let bytes = response.bytes().await.map_err(|e| MetadataError::Request {
        url: metadata_url.clone(),
        source: Box::new(e),
    })?;
    let metadata: PersonServerMetadata =
        serde_json::from_slice(&bytes).map_err(|e| MetadataError::Decode {
            url: metadata_url,
            source: e,
        })?;
    metadata.validate()?;
    Ok(metadata)
}

fn resolve_url(base: &str, url: &str) -> String {
    if url.starts_with("http://") || url.starts_with("https://") {
        url.to_string()
    } else {
        url::Url::parse(base)
            .and_then(|b| b.join(url))
            .map(|u| u.to_string())
            .unwrap_or_else(|_| url.to_string())
    }
}
