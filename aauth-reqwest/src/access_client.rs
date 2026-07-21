use std::time::{Duration, Instant};

use aauth::AccessServerClient;
use aauth::AccessServerExchangeOutcome;
use aauth::DeferredError;
use aauth::MetadataError;
use aauth::PendingInput;
use aauth::PersonServerOutboundSigner;
use aauth::SERVER_POLL_DEFAULT_MAX_SECS;
use aauth::SERVER_POLL_DEFAULT_PREFER_WAIT;
use aauth::ServerPollOptions;
use aauth::ServerPollOutcome;
use aauth::error::Result;
use aauth::parse_auth_token_response;
use aauth::parse_deferred_response;
use aauth::protocol::{
    AAuthErrorCode, AAuthProtocolError, AccessServerMetadata, AccessTokenExchangeRequest,
    ClarificationResponse, PREFER, TokenResponseBody,
};
use http::HeaderMap;
use http::header::{CONTENT_TYPE, RETRY_AFTER};
use httpsig_key::{SignOptions, SignatureKey, SignatureKeyJwt, SigningMaterial, sign};
use reqwest::Client;
use url::Url;

/// Reqwest implementation of [`AccessServerClient`] for Person Server → Access Server federation.
#[derive(Clone)]
pub struct ReqwestAccessServerClient {
    client: Client,
    signer: PersonServerOutboundSigner,
}

impl ReqwestAccessServerClient {
    pub fn new(client: Client, signer: PersonServerOutboundSigner) -> Self {
        Self { client, signer }
    }

    fn signing_material(&self) -> SigningMaterial {
        SigningMaterial {
            signing_jwk: self.signer.signing_jwk().clone(),
            signature_key: SignatureKey::Jwt(SignatureKeyJwt {
                jwt: self.signer.signature_jwt(),
            }),
        }
    }

    fn sign_headers(&self, method: &str, url: &str) -> Result<HeaderMap> {
        let (authority, path) = url_authority_path(url)?;
        let mut headers = HeaderMap::new();
        sign(
            &mut headers,
            method,
            &authority,
            &path,
            &self.signing_material(),
            &SignOptions::default(),
        )?;
        Ok(headers)
    }
}

impl AccessServerClient for ReqwestAccessServerClient {
    async fn fetch_metadata(&self, access_server_url: &str) -> Result<AccessServerMetadata> {
        let access_server_url = access_server_url.trim_end_matches('/');
        let metadata_url = format!("{access_server_url}/.well-known/aauth-access.json");
        let metadata_resp =
            self.client
                .get(&metadata_url)
                .send()
                .await
                .map_err(|e| MetadataError::Request {
                    url: metadata_url.clone(),
                    source: Box::new(e),
                })?;

        if !metadata_resp.status().is_success() {
            return Err(MetadataError::HttpStatus {
                url: metadata_url.clone(),
                status: metadata_resp.status().as_u16(),
            }
            .into());
        }

        let metadata: AccessServerMetadata =
            metadata_resp
                .json()
                .await
                .map_err(|e| MetadataError::Request {
                    url: metadata_url,
                    source: Box::new(e),
                })?;
        Ok(metadata)
    }

    async fn exchange_token(
        &self,
        token_endpoint: &str,
        request: &AccessTokenExchangeRequest,
    ) -> Result<AccessServerExchangeOutcome> {
        let body_json = serde_json::to_string(request).map_err(DeferredError::Serialize)?;
        let mut headers = self.sign_headers("POST", token_endpoint)?;
        headers.insert(
            CONTENT_TYPE,
            http::HeaderValue::from_static("application/json"),
        );

        let mut builder = self.client.post(token_endpoint).body(body_json);
        for (name, value) in headers.iter() {
            builder = builder.header(name, value);
        }

        let response = builder.send().await.map_err(|e| MetadataError::Request {
            url: token_endpoint.to_string(),
            source: Box::new(e),
        })?;

        let status = response.status().as_u16();
        let access_server_url = origin_of(token_endpoint)?;

        if status == 402 {
            // Spec: `#as-token-endpoint` Payment required — settle then poll Location.
            // Stub: payment settlement is not implemented; treat as hard error.
            return Err(DeferredError::PaymentNotRequirement.into());
        }

        if status == 202 {
            let headers = response_headers_to_http(response.headers());
            let body_bytes = response.bytes().await.map_err(|e| MetadataError::Request {
                url: token_endpoint.to_string(),
                source: Box::new(e),
            })?;
            let parsed =
                parse_deferred_response(status, &headers, &body_bytes, &access_server_url)?;
            return Ok(AccessServerExchangeOutcome::Deferred {
                requirement: parsed.requirement,
                as_pending_url: parsed.location,
            });
        }

        if !response.status().is_success() {
            return Err(MetadataError::HttpStatus {
                url: token_endpoint.to_string(),
                status,
            }
            .into());
        }

        let token_body: TokenResponseBody =
            response.json().await.map_err(|e| MetadataError::Request {
                url: token_endpoint.to_string(),
                source: Box::new(e),
            })?;

        Ok(AccessServerExchangeOutcome::Complete(token_body))
    }

    async fn resume_pending(
        &self,
        pending_url: &str,
        input: &PendingInput,
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

        let mut builder = self
            .client
            .post(pending_url)
            .header(CONTENT_TYPE, content_type);
        let signed = self.sign_headers("POST", pending_url)?;
        for (name, value) in signed.iter() {
            builder = builder.header(name, value);
        }
        builder = builder.body(body);

        let response = builder.send().await.map_err(|e| DeferredError::Transport {
            source: Box::new(e),
        })?;

        let status = response.status().as_u16();
        let body = response.bytes().await.map_err(|e| DeferredError::Transport {
            source: Box::new(e),
        })?;

        if status == 200 {
            return parse_auth_token_response(status, &body).map(Some);
        }

        if matches!(status, 202 | 403 | 410) {
            return Ok(None);
        }

        Err(DeferredError::PostFailed(status).into())
    }

    async fn poll_pending(
        &self,
        access_server_url: &str,
        options: ServerPollOptions,
    ) -> Result<ServerPollOutcome> {
        let max_duration = options
            .max_poll_duration_secs
            .unwrap_or(SERVER_POLL_DEFAULT_MAX_SECS);
        let prefer_wait = options
            .prefer_wait
            .unwrap_or(SERVER_POLL_DEFAULT_PREFER_WAIT);
        let deadline = Instant::now() + Duration::from_secs(max_duration);
        let poll_url = options.location_url.clone();
        let mut backoff_ms = 1000u64;

        while Instant::now() < deadline {
            let response = self
                .client
                .get(&poll_url)
                .header(PREFER, format!("wait={prefer_wait}"))
                .send()
                .await
                .map_err(|e| DeferredError::Transport {
                    source: Box::new(e),
                })?;

            let status = response.status().as_u16();
            let headers = response_headers_to_http(response.headers());
            let retry_after = parse_retry_after(&headers);
            let body = response.bytes().await.map_err(|e| DeferredError::Transport {
                source: Box::new(e),
            })?;

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
                    AAuthProtocolError::with_description(
                        AAuthErrorCode::AccessDenied,
                        "Access denied",
                    )
                });
                return Ok(ServerPollOutcome::Error(err));
            }

            if status == 202 {
                let parsed =
                    parse_deferred_response(status, &headers, &body, access_server_url)?;
                return Ok(ServerPollOutcome::Deferred {
                    requirement: parsed.requirement,
                    location_url: parsed.location,
                });
            }

            if status == 503 {
                let wait_ms = retry_after.map(|s| s * 1000).unwrap_or(backoff_ms);
                tokio::time::sleep(Duration::from_millis(wait_ms)).await;
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
}

fn url_authority_path(url: &str) -> Result<(String, String)> {
    let parsed = Url::parse(url).map_err(DeferredError::InvalidUrl)?;
    let authority = parsed
        .host_str()
        .ok_or(DeferredError::MissingHost)?
        .to_string();
    let authority = match parsed.port() {
        Some(port) => format!("{authority}:{port}"),
        None => authority,
    };
    let path = parsed.path().to_string();
    Ok((authority, path))
}

fn origin_of(url: &str) -> Result<String> {
    let parsed = Url::parse(url).map_err(DeferredError::InvalidUrl)?;
    let host = parsed.host_str().ok_or(DeferredError::MissingHost)?;
    let origin = match parsed.port() {
        Some(port) => format!("{}://{host}:{port}", parsed.scheme()),
        None => format!("{}://{host}", parsed.scheme()),
    };
    Ok(origin)
}

fn response_headers_to_http(headers: &reqwest::header::HeaderMap) -> http::HeaderMap {
    let mut map = http::HeaderMap::new();
    for (name, value) in headers.iter() {
        if let (Ok(n), Ok(v)) = (
            http::HeaderName::from_bytes(name.as_str().as_bytes()),
            http::HeaderValue::from_bytes(value.as_bytes()),
        ) {
            map.insert(n, v);
        }
    }
    map
}

fn parse_retry_after(headers: &HeaderMap) -> Option<u64> {
    headers
        .get(RETRY_AFTER)
        .and_then(|v| v.to_str().ok())
        .and_then(|v| v.parse().ok())
}

#[cfg(test)]
mod tests {
    use super::*;
    use aauth::DeferRequirement;
    use aauth::PendingBody;
    use aauth::TestKeys;
    use aauth::AAUTH_REQUIREMENT;

    fn test_client() -> ReqwestAccessServerClient {
        let keys = TestKeys::generate();
        ReqwestAccessServerClient::new(
            Client::new(),
            PersonServerOutboundSigner::new(keys, "https://ps.example"),
        )
    }

    #[tokio::test]
    async fn poll_pending_returns_auth_token_on_200() {
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

        let client = test_client();
        let outcome = client
            .poll_pending(
                &mock.uri(),
                ServerPollOptions {
                    location_url: format!("{}/pending/abc", mock.uri()),
                    max_poll_duration_secs: Some(2),
                    prefer_wait: Some(1),
                },
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
    async fn resume_pending_returns_token_on_200() {
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

        let client = test_client();
        let token = client
            .resume_pending(
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
    async fn poll_pending_returns_deferred_on_202() {
        let mock = wiremock::MockServer::start().await;
        let requirement = DeferRequirement::Clarification {
            question: "Why?".into(),
            timeout: None,
        };
        let location = format!("{}/pending/abc", mock.uri());
        let body = PendingBody::for_created(&requirement).expect("pending body");
        let challenge = requirement.header_challenge().expect("challenge");
        let aauth_req = challenge.to_header();

        let template = wiremock::ResponseTemplate::new(202)
            .insert_header(http::header::LOCATION, location.as_str())
            .insert_header(http::header::RETRY_AFTER, "0")
            .insert_header(http::header::CACHE_CONTROL, "no-store")
            .insert_header(AAUTH_REQUIREMENT, aauth_req.as_str())
            .insert_header(http::header::CONTENT_TYPE, "application/json")
            .set_body_json(body);

        wiremock::Mock::given(wiremock::matchers::method("GET"))
            .and(wiremock::matchers::path("/pending/abc"))
            .respond_with(template)
            .mount(&mock)
            .await;

        let client = test_client();
        let outcome = client
            .poll_pending(
                &mock.uri(),
                ServerPollOptions {
                    location_url: location.clone(),
                    max_poll_duration_secs: Some(2),
                    prefer_wait: Some(1),
                },
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
