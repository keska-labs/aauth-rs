use std::collections::HashMap;
use std::time::{Duration, Instant};

use tokio::time::sleep;

use crate::client::SignedFetch;
use crate::error::{AAuthError, Result};
use crate::headers::parse_aauth_requirement;
use crate::http::HttpRequest;
use crate::types::{
    AAuthProtocolError, ClarificationChallenge, ClarificationResponse, RequirementLevel,
};

const DEFAULT_MAX_POLL_DURATION: u64 = 300;
const DEFAULT_PREFER_WAIT: u64 = 45;

#[derive(Clone)]
pub struct DeferredOptions {
    pub signed_fetch: SignedFetch,
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

#[derive(Debug, Clone)]
pub struct DeferredResult {
    pub response: crate::http::HttpResponse,
    pub error: Option<AAuthProtocolError>,
}

pub async fn poll_deferred(options: DeferredOptions) -> Result<DeferredResult> {
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
        let response = options.signed_fetch.as_ref()(HttpRequest {
            method: "GET".into(),
            url: poll_url.clone(),
            headers: HashMap::from([("prefer".to_string(), format!("wait={DEFAULT_PREFER_WAIT}"))]),
            body: None,
        })
        .await?;

        let status = response.status;

        if matches!(status, 200 | 400 | 401 | 403 | 408 | 410 | 500) {
            return Ok(DeferredResult {
                error: parse_error_body(&response),
                response,
            });
        }

        if status == 202 {
            if let Some(on_clarification) = &options.on_clarification {
                if response
                    .header("content-type")
                    .unwrap_or("")
                    .contains("application/json")
                {
                    if let Ok(body) = response.json::<ClarificationChallenge>() {
                        let answer = on_clarification(body.clarification).await;
                        let payload = ClarificationResponse {
                            clarification_response: answer,
                        };
                        let _ = options.signed_fetch.as_ref()(HttpRequest {
                            method: "POST".into(),
                            url: poll_url.clone(),
                            headers: HashMap::from([(
                                "content-type".to_string(),
                                "application/json".to_string(),
                            )]),
                            body: Some(
                                serde_json::to_string(&payload)
                                    .map_err(|e| AAuthError::Message(e.to_string()))?
                                    .into_bytes(),
                            ),
                        })
                        .await?;
                    }
                }
            }

            if let Some(header) = response.header("aauth-requirement") {
                if let Ok(challenge) = parse_aauth_requirement(header) {
                    if challenge.requirement == RequirementLevel::Interaction {
                        if let (Some(url), Some(code)) = (challenge.url, challenge.code) {
                            if let Some(on_interaction) = &options.on_interaction {
                                on_interaction(url, code);
                            }
                        }
                    }
                }
            }

            let wait_ms = retry_delay(&response, backoff_ms);
            sleep(Duration::from_millis(wait_ms)).await;
            backoff_ms = (backoff_ms * 2).min(5000);
            continue;
        }

        if status == 503 {
            let wait_ms = retry_delay(&response, backoff_ms);
            sleep(Duration::from_millis(wait_ms)).await;
            backoff_ms = (backoff_ms * 2).min(30000);
            continue;
        }

        return Ok(DeferredResult {
            error: parse_error_body(&response),
            response,
        });
    }

    Err(AAuthError::Message(format!(
        "Polling timed out after {max_poll_duration}s"
    )))
}

fn retry_delay(response: &crate::http::HttpResponse, fallback_ms: u64) -> u64 {
    response
        .header("retry-after")
        .and_then(|v| v.parse::<u64>().ok())
        .map(|seconds| seconds * 1000)
        .unwrap_or(fallback_ms)
}

fn parse_error_body(response: &crate::http::HttpResponse) -> Option<AAuthProtocolError> {
    if response.status == 200 {
        return None;
    }
    if !response
        .header("content-type")
        .unwrap_or("")
        .contains("application/json")
    {
        return None;
    }
    response.json().ok()
}
