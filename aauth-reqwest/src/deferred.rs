use std::future::Future;
use std::time::{Duration, Instant};

use aauth::DeferredError;
use aauth::MetadataError;
use aauth::agent::auth::{AgentOptions, ClarificationCallback, InteractionCallback};
use aauth::protocol::{
    AAUTH_REQUIREMENT, AAuthChallenge, AAuthProtocolError, ClarificationChallenge,
    ClarificationResponse, PREFER,
};
use http::header::{CONTENT_TYPE, RETRY_AFTER};
use http::{Method, Request as HttpRequest};
use reqwest::{Request, Response};
use tokio::time::sleep;

use crate::error::Result;
use crate::send::SignedSend;

const DEFAULT_MAX_POLL_DURATION: u64 = 300;
const DEFAULT_PREFER_WAIT: u64 = 45;

#[derive(Clone)]
pub struct AgentDeferredOptions {
    pub(crate) location_url: String,
    pub(crate) interaction_url: Option<String>,
    pub(crate) interaction_code: Option<String>,
    pub(crate) on_interaction: Option<InteractionCallback>,
    pub(crate) on_clarification: Option<ClarificationCallback>,
    pub(crate) max_poll_duration_secs: Option<u64>,
}

#[derive(Clone)]
pub struct AgentDeferredOptionsBuilder {
    location_url: String,
    interaction_url: Option<String>,
    interaction_code: Option<String>,
    on_interaction: Option<InteractionCallback>,
    on_clarification: Option<ClarificationCallback>,
    max_poll_duration_secs: Option<u64>,
}

impl AgentDeferredOptions {
    pub fn builder(location_url: impl Into<String>) -> AgentDeferredOptionsBuilder {
        AgentDeferredOptionsBuilder::new(location_url)
    }

    /// Build deferred poll options from shared [`AgentOptions`] callbacks/limits.
    pub(crate) fn from_agent_options(
        options: &AgentOptions,
        location_url: String,
        interaction_url: Option<String>,
        interaction_code: Option<String>,
    ) -> Self {
        let mut builder = Self::builder(location_url);
        if let (Some(url), Some(code)) = (interaction_url, interaction_code) {
            builder = builder.interaction(url, code);
        }
        if let Some(cb) = options.on_interaction().cloned() {
            builder = builder.on_interaction(cb);
        }
        if let Some(cb) = options.on_clarification().cloned() {
            builder = builder.on_clarification(cb);
        }
        if let Some(secs) = options.max_poll_duration_secs() {
            builder = builder.max_poll_duration_secs(secs);
        }
        builder.build()
    }
}

impl AgentDeferredOptionsBuilder {
    pub fn new(location_url: impl Into<String>) -> Self {
        Self {
            location_url: location_url.into(),
            interaction_url: None,
            interaction_code: None,
            on_interaction: None,
            on_clarification: None,
            max_poll_duration_secs: None,
        }
    }

    pub fn interaction(mut self, url: impl Into<String>, code: impl Into<String>) -> Self {
        self.interaction_url = Some(url.into());
        self.interaction_code = Some(code.into());
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

    pub fn build(self) -> AgentDeferredOptions {
        AgentDeferredOptions {
            location_url: self.location_url,
            interaction_url: self.interaction_url,
            interaction_code: self.interaction_code,
            on_interaction: self.on_interaction,
            on_clarification: self.on_clarification,
            max_poll_duration_secs: self.max_poll_duration_secs,
        }
    }
}

#[derive(Debug)]
pub struct DeferredResult {
    pub response: Response,
    pub error: Option<AAuthProtocolError>,
}

pub async fn poll_deferred<F, Fut>(options: AgentDeferredOptions, send: F) -> Result<DeferredResult>
where
    F: FnMut(Request) -> Fut + Send,
    Fut: Future<Output = Result<Response>> + Send,
{
    struct Adapter<F>(F);

    #[async_trait::async_trait]
    impl<F, Fut> SignedSend for Adapter<F>
    where
        F: FnMut(Request) -> Fut + Send,
        Fut: Future<Output = Result<Response>> + Send,
    {
        async fn send(&mut self, req: Request) -> Result<Response> {
            (self.0)(req).await
        }
    }

    poll_deferred_with(options, &mut Adapter(send)).await
}

pub(crate) async fn poll_deferred_with<S: SignedSend>(
    options: AgentDeferredOptions,
    send: &mut S,
) -> Result<DeferredResult> {
    let max_poll_duration = options
        .max_poll_duration_secs
        .unwrap_or(DEFAULT_MAX_POLL_DURATION);
    let deadline = Instant::now() + Duration::from_secs(max_poll_duration);

    if let (Some(url), Some(code)) = (&options.interaction_url, &options.interaction_code) {
        if let Some(on_interaction) = &options.on_interaction {
            on_interaction(url.clone(), code.clone());
        }
    }

    let mut backoff_ms = 1000u64;
    let poll_url = options.location_url.clone();

    while Instant::now() < deadline {
        let prefer = format!("wait={DEFAULT_PREFER_WAIT}");
        let http_req = HttpRequest::builder()
            .method(Method::GET)
            .uri(&poll_url)
            .header(PREFER, &prefer)
            .body(Vec::new())
            .expect("valid http request");
        let response = send
            .send(Request::try_from(http_req).expect("valid reqwest request"))
            .await?;

        let status = response.status().as_u16();
        let retry_after = response
            .headers()
            .get(RETRY_AFTER)
            .and_then(|v| v.to_str().ok())
            .and_then(|v| v.parse::<u64>().ok());
        let requirement_header = response
            .headers()
            .get(AAUTH_REQUIREMENT)
            .and_then(|v| v.to_str().ok())
            .map(str::to_string);
        let is_json = header_contains_json(&response);

        if matches!(status, 200 | 400 | 401 | 403 | 408 | 410 | 500) {
            let (response, error) = split_error(response).await?;
            return Ok(DeferredResult { error, response });
        }

        if status == 202 {
            if let Some(on_clarification) = &options.on_clarification {
                if is_json {
                    if let Ok(body) = response.json::<ClarificationChallenge>().await {
                        let answer = on_clarification(body.clarification).await;
                        let payload = ClarificationResponse {
                            clarification_response: answer,
                        };
                        let body =
                            serde_json::to_string(&payload).map_err(DeferredError::Serialize)?;
                        let http_req = HttpRequest::builder()
                            .method(Method::POST)
                            .uri(&poll_url)
                            .header(CONTENT_TYPE, "application/json")
                            .body(body.into_bytes())
                            .expect("valid http request");
                        let _ = send
                            .send(Request::try_from(http_req).expect("valid reqwest request"))
                            .await?;
                    }
                }
            }

            if let Some(header) = requirement_header {
                if let Ok(AAuthChallenge::Interaction { url, code }) =
                    AAuthChallenge::from_header(&header)
                {
                    if let Some(on_interaction) = &options.on_interaction {
                        on_interaction(url, code);
                    }
                }
            }

            let wait_ms = retry_delay_from_secs(retry_after, backoff_ms);
            sleep(Duration::from_millis(wait_ms)).await;
            backoff_ms = (backoff_ms * 2).min(5000);
            continue;
        }

        if status == 503 {
            let wait_ms = retry_delay_from_secs(retry_after, backoff_ms);
            sleep(Duration::from_millis(wait_ms)).await;
            backoff_ms = (backoff_ms * 2).min(30000);
            continue;
        }

        return Ok({
            let (response, error) = split_error(response).await?;
            DeferredResult { error, response }
        });
    }

    Err(DeferredError::TimedOut(max_poll_duration).into())
}

fn retry_delay_from_secs(retry_after: Option<u64>, fallback_ms: u64) -> u64 {
    retry_after
        .map(|seconds| seconds * 1000)
        .unwrap_or(fallback_ms)
}

fn header_contains_json(response: &Response) -> bool {
    headers_contain_json(response.headers())
}

async fn split_error(response: Response) -> Result<(Response, Option<AAuthProtocolError>)> {
    let status = response.status();
    let headers = response.headers().clone();
    let url = response.url().to_string();
    let bytes = response.bytes().await.map_err(|e| MetadataError::Request {
        url: url.clone(),
        source: Box::new(e),
    })?;
    let error = if !status.is_success() && headers_contain_json(&headers) {
        serde_json::from_slice(&bytes).ok()
    } else {
        None
    };
    let mut builder = http::Response::builder().status(status);
    for (name, value) in headers.iter() {
        builder = builder.header(name, value);
    }
    let http_response = builder
        .body(bytes.to_vec())
        .map_err(|e| MetadataError::Request {
            url,
            source: Box::new(e),
        })?;
    Ok((Response::from(http_response), error))
}

fn headers_contain_json(headers: &http::HeaderMap) -> bool {
    headers
        .get(CONTENT_TYPE)
        .and_then(|v| v.to_str().ok())
        .is_some_and(|v| v.contains("application/json"))
}
