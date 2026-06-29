use std::future::Future;
use std::time::{Duration, Instant};

use http::{Method, Request as HttpRequest};
use reqwest::{Request, Response};
use tokio::time::sleep;

use crate::client::send::SignedSend;
use crate::error::{AAuthError, Result};
use crate::headers::parse_aauth_requirement;
use crate::types::{
    AAuthProtocolError, ClarificationChallenge, ClarificationResponse, RequirementLevel,
};

const DEFAULT_MAX_POLL_DURATION: u64 = 300;
const DEFAULT_PREFER_WAIT: u64 = 45;

#[derive(Clone)]
pub struct DeferredOptions {
    pub location_url: String,
    pub interaction_url: Option<String>,
    pub interaction_code: Option<String>,
    pub on_interaction: Option<InteractionCallback>,
    pub on_clarification: Option<ClarificationCallback>,
    pub max_poll_duration: Option<u64>,
}

pub type InteractionCallback = std::sync::Arc<dyn Fn(String, String) + Send + Sync>;

pub type ClarificationCallback = std::sync::Arc<
    dyn Fn(String) -> std::pin::Pin<Box<dyn std::future::Future<Output = String> + Send>>
        + Send
        + Sync,
>;

#[derive(Debug)]
pub struct DeferredResult {
    pub response: Response,
    pub error: Option<AAuthProtocolError>,
}

pub async fn poll_deferred<F, Fut>(
    options: DeferredOptions,
    send: F,
) -> Result<DeferredResult>
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
    options: DeferredOptions,
    send: &mut S,
) -> Result<DeferredResult> {
    let max_poll_duration = options
        .max_poll_duration
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
            .header("prefer", &prefer)
            .body(Vec::new())
            .expect("valid http request");
        let response = send
            .send(Request::try_from(http_req).expect("valid reqwest request"))
            .await?;

        let status = response.status().as_u16();
        let retry_after = response
            .headers()
            .get("retry-after")
            .and_then(|v| v.to_str().ok())
            .and_then(|v| v.parse::<u64>().ok());
        let requirement_header = response
            .headers()
            .get("aauth-requirement")
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
                        let body = serde_json::to_string(&payload)
                            .map_err(|e| AAuthError::Message(e.to_string()))?;
                        let http_req = HttpRequest::builder()
                            .method(Method::POST)
                            .uri(&poll_url)
                            .header("content-type", "application/json")
                            .body(body.into_bytes())
                            .expect("valid http request");
                        let _ = send
                            .send(Request::try_from(http_req).expect("valid reqwest request"))
                            .await?;
                    }
                }
            }

            if let Some(header) = requirement_header {
                if let Ok(challenge) = parse_aauth_requirement(&header) {
                    if challenge.requirement == RequirementLevel::Interaction {
                        if let (Some(url), Some(code)) = (challenge.url, challenge.code) {
                            if let Some(on_interaction) = &options.on_interaction {
                                on_interaction(url, code);
                            }
                        }
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

    Err(AAuthError::Message(format!(
        "Polling timed out after {max_poll_duration}s"
    )))
}

fn retry_delay_from_secs(retry_after: Option<u64>, fallback_ms: u64) -> u64 {
    retry_after
        .map(|seconds| seconds * 1000)
        .unwrap_or(fallback_ms)
}

fn header_contains_json(response: &Response) -> bool {
    response
        .headers()
        .get("content-type")
        .and_then(|v| v.to_str().ok())
        .is_some_and(|v| v.contains("application/json"))
}

async fn split_error(response: Response) -> Result<(Response, Option<AAuthProtocolError>)> {
    let status = response.status();
    let headers = response.headers().clone();
    let bytes = response
        .bytes()
        .await
        .map_err(|e| AAuthError::Message(e.to_string()))?;
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
        .map_err(|e| AAuthError::Message(e.to_string()))?;
    Ok((Response::from(http_response), error))
}

fn headers_contain_json(headers: &http::HeaderMap) -> bool {
    headers
        .get("content-type")
        .and_then(|v| v.to_str().ok())
        .is_some_and(|v| v.contains("application/json"))
}