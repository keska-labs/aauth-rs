use std::time::{Duration, Instant};

use reqwest::header::HeaderMap;
use tokio::time::sleep;

use crate::error::{DeferredError, Result};
use crate::jwt::OkpSigningJwk;
use crate::protocol::{
    AAuthErrorCode, AAuthProtocolError, ClarificationResponse, TokenResponseBody,
};
use crate::signature::apply_outbound_signature;

use super::parse::{parse_auth_token_response, parse_deferred_response};
use super::types::{DeferRequirement, PendingInput};

const DEFAULT_MAX_POLL_DURATION_SECS: u64 = 300;
const DEFAULT_PREFER_WAIT: u64 = 45;

/// Signs outbound HTTP requests to pending URLs (e.g. Person Server → Access Server).
pub trait OutboundSignatureProvider: Send + Sync {
    fn signature_jwt(&self) -> String;
    fn signing_jwk(&self) -> &OkpSigningJwk;
}

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
    signer: Option<&dyn OutboundSignatureProvider>,
) -> Result<Option<TokenResponseBody>> {
    let (body, content_type) = match input {
        PendingInput::ClarificationResponse(answer) => (
            serde_json::to_string(&ClarificationResponse {
                clarification_response: answer.clone(),
            })
            .map_err(DeferredError::Serialize)?,
            "application/json",
        ),
        PendingInput::ClaimsSubmission(claims) => (
            serde_json::to_string(claims).map_err(DeferredError::Serialize)?,
            "application/json",
        ),
        PendingInput::InteractionCompleted | PendingInput::Cancelled => {
            ("{}".into(), "application/json")
        }
        PendingInput::UpdatedToken(updated) => (
            serde_json::to_string(updated).map_err(DeferredError::Serialize)?,
            "application/json",
        ),
    };

    let mut request = client.post(url).header("content-type", content_type);
    if let Some(signer) = signer {
        let parsed = url::Url::parse(url).map_err(DeferredError::InvalidUrl)?;
        let authority = parsed.host_str().ok_or(DeferredError::MissingHost)?;
        let authority = match parsed.port() {
            Some(port) => format!("{authority}:{port}"),
            None => authority.to_string(),
        };
        let path = parsed.path().to_string();
        let mut headers = HeaderMap::new();
        apply_outbound_signature(
            &mut headers,
            "POST",
            &authority,
            &path,
            &signer.signature_jwt(),
            signer.signing_jwk(),
            None,
        )?;
        for (name, value) in headers.iter() {
            request = request.header(name, value);
        }
    }
    request = request.body(body);

    let response = request.send().await.map_err(DeferredError::Transport)?;

    let status = response.status().as_u16();
    let body = response
        .bytes()
        .await
        .map_err(DeferredError::ResponseBody)?;

    if status == 200 {
        return parse_auth_token_response(status, &body).map(Some);
    }

    if matches!(status, 202 | 403 | 410) {
        return Ok(None);
    }

    Err(DeferredError::PostFailed(status).into())
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
            .map_err(DeferredError::Transport)?;

        let status = response.status().as_u16();
        let headers = crate::http_util::response_headers_to_http(response.headers());
        let retry_after = parse_retry_after(&headers);
        let body = response
            .bytes()
            .await
            .map_err(DeferredError::ResponseBody)?;

        if status == 200 {
            if let Ok(token) = parse_auth_token_response(status, &body) {
                return Ok(ServerPollOutcome::AuthToken(token));
            }
            return Err(DeferredError::MissingAuthTokenBody.into());
        }

        if status == 410 {
            return Ok(ServerPollOutcome::Gone);
        }

        if status == 403 {
            let err: AAuthProtocolError = serde_json::from_slice(&body).unwrap_or_else(|_| {
                AAuthProtocolError::with_description(AAuthErrorCode::AccessDenied, "Access denied")
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

        return Err(DeferredError::UnexpectedStatus {
            expected: 200,
            got: status,
        }
        .into());
    }

    Err(DeferredError::TimedOut(max_duration).into())
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
            None,
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
        let location = format!("{}/pending/abc", mock.uri());
        let body = crate::protocol::PendingBody::for_created(&requirement).expect("pending body");
        let challenge = requirement.header_challenge().expect("challenge");
        let aauth_req = challenge.to_header();

        let template = wiremock::ResponseTemplate::new(202)
            .insert_header("Location", location.as_str())
            .insert_header("Retry-After", "0")
            .insert_header("Cache-Control", "no-store")
            .insert_header("AAuth-Requirement", aauth_req.as_str())
            .insert_header("Content-Type", "application/json")
            .set_body_json(body);

        wiremock::Mock::given(wiremock::matchers::method("GET"))
            .and(wiremock::matchers::path("/pending/abc"))
            .respond_with(template)
            .mount(&mock)
            .await;

        let client = reqwest::Client::new();
        let outcome = poll_pending_http(
            &client,
            ServerPollOptions {
                location_url: location.clone(),
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
                location_url: location,
            }
        );
    }
}
