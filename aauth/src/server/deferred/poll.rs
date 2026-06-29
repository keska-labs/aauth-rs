use std::time::{Duration, Instant};

use reqwest::header::{HeaderMap, HeaderName, HeaderValue};
use tokio::time::sleep;

use crate::error::{AAuthError, Result};
use crate::types::{AAuthProtocolError, ClarificationResponse, TokenResponseBody};

use super::parse::{parse_auth_token_response, parse_deferred_response};
use super::types::{DeferRequirement, PendingInput};

const DEFAULT_MAX_POLL_DURATION_SECS: u64 = 300;
const DEFAULT_PREFER_WAIT: u64 = 45;

#[derive(Debug, Clone)]
pub struct ServerPollOptions {
    pub location_url: String,
    pub max_poll_duration_secs: Option<u64>,
    pub prefer_wait: Option<u64>,
}

impl ServerPollOptions {
    pub fn new(location_url: impl Into<String>) -> Self {
        Self {
            location_url: location_url.into(),
            max_poll_duration_secs: None,
            prefer_wait: None,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ServerPollOutcome {
    AuthToken(TokenResponseBody),
    Deferred {
        requirement: DeferRequirement,
        location_url: String,
    },
    Error(AAuthProtocolError),
    Gone,
}

pub async fn post_pending_input(
    client: &reqwest::Client,
    url: &str,
    input: &PendingInput,
) -> Result<Option<TokenResponseBody>> {
    let (body, content_type) = match input {
        PendingInput::ClarificationResponse(answer) => (
            serde_json::to_string(&ClarificationResponse {
                clarification_response: answer.clone(),
            })
            .map_err(|e| AAuthError::Message(e.to_string()))?,
            "application/json",
        ),
        PendingInput::ClaimsSubmission(claims) => (
            serde_json::to_string(claims).map_err(|e| AAuthError::Message(e.to_string()))?,
            "application/json",
        ),
        PendingInput::InteractionCompleted | PendingInput::Cancelled => {
            ("{}".into(), "application/json")
        }
    };

    let mut request = client.post(url).header("content-type", content_type);
    request = request.body(body);

    let response = request
        .send()
        .await
        .map_err(|e| AAuthError::Message(e.to_string()))?;

    let status = response.status().as_u16();
    let body = response
        .bytes()
        .await
        .map_err(|e| AAuthError::Message(e.to_string()))?;

    if status == 200 {
        return parse_auth_token_response(status, &body).map(Some);
    }

    if matches!(status, 202 | 403 | 410) {
        return Ok(None);
    }

    Err(AAuthError::Message(format!(
        "pending POST failed with status {status}"
    )))
}

pub async fn poll_pending_http(
    client: &reqwest::Client,
    options: ServerPollOptions,
    base_url: &str,
) -> Result<ServerPollOutcome> {
    let max_duration = options
        .max_poll_duration_secs
        .unwrap_or(DEFAULT_MAX_POLL_DURATION_SECS);
    let prefer_wait = options.prefer_wait.unwrap_or(DEFAULT_PREFER_WAIT);
    let deadline = Instant::now() + Duration::from_secs(max_duration);
    let poll_url = options.location_url.clone();
    let mut backoff_ms = 1000u64;

    while Instant::now() < deadline {
        let response = client
            .get(&poll_url)
            .header("prefer", format!("wait={prefer_wait}"))
            .send()
            .await
            .map_err(|e| AAuthError::Message(e.to_string()))?;

        let status = response.status().as_u16();
        let headers = response_headers_to_http(&response.headers());
        let retry_after = parse_retry_after(&headers);
        let body = response
            .bytes()
            .await
            .map_err(|e| AAuthError::Message(e.to_string()))?;

        if status == 200 {
            if let Ok(token) = parse_auth_token_response(status, &body) {
                return Ok(ServerPollOutcome::AuthToken(token));
            }
            return Err(AAuthError::Message(
                "pending poll returned 200 without auth token body".into(),
            ));
        }

        if status == 410 {
            return Ok(ServerPollOutcome::Gone);
        }

        if status == 403 {
            let err: AAuthProtocolError =
                serde_json::from_slice(&body).unwrap_or_else(|_| AAuthProtocolError {
                    error: "access_denied".into(),
                    error_description: Some("Access denied".into()),
                    error_uri: None,
                });
            return Ok(ServerPollOutcome::Error(err));
        }

        if status == 202 {
            let parsed = parse_deferred_response(status, &headers, &body, base_url)?;
            return Ok(ServerPollOutcome::Deferred {
                requirement: parsed.requirement,
                location_url: parsed.location,
            });
        }

        if status == 503 {
            let wait_ms = retry_after.map(|s| s * 1000).unwrap_or(backoff_ms);
            sleep(Duration::from_millis(wait_ms)).await;
            backoff_ms = (backoff_ms * 2).min(30_000);
            continue;
        }

        return Err(AAuthError::Message(format!(
            "unexpected pending poll status {status}"
        )));
    }

    Err(AAuthError::Message(format!(
        "pending poll timed out after {max_duration}s"
    )))
}

fn response_headers_to_http(headers: &reqwest::header::HeaderMap) -> HeaderMap {
    let mut map = HeaderMap::new();
    for (name, value) in headers.iter() {
        if let (Ok(n), Ok(v)) = (
            HeaderName::from_bytes(name.as_str().as_bytes()),
            HeaderValue::from_bytes(value.as_bytes()),
        ) {
            map.insert(n, v);
        }
    }
    map
}

fn parse_retry_after(headers: &HeaderMap) -> Option<u64> {
    headers
        .get("retry-after")
        .and_then(|v| v.to_str().ok())
        .and_then(|v| v.parse().ok())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::server::deferred::build_accepted;

    #[tokio::test]
    async fn poll_pending_http_returns_auth_token_on_200() {
        let mock = wiremock::MockServer::start().await;
        wiremock::Mock::given(wiremock::matchers::method("GET"))
            .and(wiremock::matchers::path("/pending/abc"))
            .respond_with(
                wiremock::ResponseTemplate::new(200).set_body_json(serde_json::json!({
                    "auth_token": "jwt.example",
                    "expires_in": 3600,
                })),
            )
            .mount(&mock)
            .await;

        let client = reqwest::Client::new();
        let outcome = poll_pending_http(
            &client,
            ServerPollOptions {
                location_url: format!("{}/pending/abc", mock.uri()),
                max_poll_duration_secs: Some(2),
                prefer_wait: Some(1),
            },
            &mock.uri(),
        )
        .await
        .expect("poll");

        assert_eq!(
            outcome,
            ServerPollOutcome::AuthToken(TokenResponseBody {
                auth_token: "jwt.example".into(),
                expires_in: 3600,
            })
        );
    }

    #[tokio::test]
    async fn post_pending_input_returns_token_on_200() {
        let mock = wiremock::MockServer::start().await;
        wiremock::Mock::given(wiremock::matchers::method("POST"))
            .and(wiremock::matchers::path("/pending/abc"))
            .respond_with(
                wiremock::ResponseTemplate::new(200).set_body_json(serde_json::json!({
                    "auth_token": "jwt.example",
                    "expires_in": 3600,
                })),
            )
            .mount(&mock)
            .await;

        let client = reqwest::Client::new();
        let token = post_pending_input(
            &client,
            &format!("{}/pending/abc", mock.uri()),
            &PendingInput::InteractionCompleted,
        )
        .await
        .expect("post");

        assert_eq!(
            token,
            Some(TokenResponseBody {
                auth_token: "jwt.example".into(),
                expires_in: 3600,
            })
        );
    }

    #[tokio::test]
    async fn poll_pending_http_returns_deferred_on_202() {
        let mock = wiremock::MockServer::start().await;
        let requirement = DeferRequirement::Clarification {
            question: "Why?".into(),
            timeout: None,
        };
        let accepted =
            build_accepted(&format!("{}/pending/abc", mock.uri()), &requirement).expect("accepted");

        let mut template = wiremock::ResponseTemplate::new(202);
        for (name, value) in accepted.headers.iter() {
            template = template.insert_header(name.as_str(), value.to_str().unwrap());
        }
        template = template.set_body_string(accepted.body.to_string());

        wiremock::Mock::given(wiremock::matchers::method("GET"))
            .and(wiremock::matchers::path("/pending/abc"))
            .respond_with(template)
            .mount(&mock)
            .await;

        let client = reqwest::Client::new();
        let outcome = poll_pending_http(
            &client,
            ServerPollOptions {
                location_url: format!("{}/pending/abc", mock.uri()),
                max_poll_duration_secs: Some(2),
                prefer_wait: Some(1),
            },
            &mock.uri(),
        )
        .await
        .expect("poll");

        assert_eq!(
            outcome,
            ServerPollOutcome::Deferred {
                requirement,
                location_url: format!("{}/pending/abc", mock.uri()),
            }
        );
    }
}
