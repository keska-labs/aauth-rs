use std::future::Future;
use std::sync::Arc;

use http::{Method, Request as HttpRequest};
use reqwest::{Request, Response};

use crate::client::injector::InteractionCallback;
use crate::client::reqwest::deferred::{DeferredOptions, poll_deferred_with};
use crate::client::reqwest::send::SignedSend;
use crate::error::{AAuthError, Result};
use crate::headers::parse_aauth_requirement;
use crate::types::{
    AAuthProtocolError, PersonServerMetadata, RequirementLevel, TokenExchangeRequest,
    TokenResponseBody,
};

const PREFER_WAIT: u64 = 45;

#[derive(Debug, Clone)]
pub struct TokenExchangeResult {
    pub auth_token: String,
    pub expires_in: u64,
}

#[derive(Clone)]
pub struct TokenExchangeOptions {
    pub person_server_url: String,
    pub person_server_metadata: Option<PersonServerMetadata>,
    pub on_metadata: Option<Arc<dyn Fn(PersonServerMetadata) + Send + Sync>>,
    pub resource_token: String,
    pub justification: Option<String>,
    pub localhost_callback: Option<String>,
    pub login_hint: Option<String>,
    pub tenant: Option<String>,
    pub domain_hint: Option<String>,
    pub capabilities: Option<Vec<String>>,
    pub prompt: Option<String>,
    pub on_interaction: Option<InteractionCallback>,
    pub on_clarification: Option<crate::client::injector::ClarificationCallback>,
    pub max_poll_duration_secs: Option<u64>,
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
                err.error_description.as_deref().unwrap_or(&err.error)
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
        justification: options.justification,
        localhost_callback: options.localhost_callback,
        login_hint: options.login_hint,
        tenant: options.tenant,
        domain_hint: options.domain_hint,
        capabilities: options.capabilities,
        prompt: options.prompt,
    };

    let token_body =
        serde_json::to_string(&body).map_err(|e| AAuthError::Message(e.to_string()))?;

    let http_req = HttpRequest::builder()
        .method(Method::POST)
        .uri(&metadata.token_endpoint)
        .header("content-type", "application/json")
        .header("prefer", format!("wait={PREFER_WAIT}"))
        .body(token_body.into_bytes())
        .expect("valid http request");
    let response = send
        .send(Request::try_from(http_req).expect("valid reqwest request"))
        .await?;

    if response.status().as_u16() == 202 {
        let location = response
            .headers()
            .get("location")
            .and_then(|v| v.to_str().ok())
            .ok_or_else(|| AAuthError::Message("202 response missing Location header".into()))?
            .to_string();

        let mut interaction_url = None;
        let mut interaction_code = None;
        if let Some(header) = response
            .headers()
            .get("aauth-requirement")
            .and_then(|v| v.to_str().ok())
        {
            if let Ok(challenge) = parse_aauth_requirement(header) {
                if challenge.requirement == RequirementLevel::Interaction {
                    interaction_url = challenge.url;
                    interaction_code = challenge.code;
                }
            }
        }

        let result = poll_deferred_with(
            DeferredOptions {
                location_url: resolve_url(&options.person_server_url, &location),
                interaction_url,
                interaction_code,
                on_interaction: options.on_interaction,
                on_clarification: options.on_clarification,
                max_poll_duration: options.max_poll_duration_secs,
            },
            send,
        )
        .await?;

        if result.response.status().is_success() {
            let parsed: TokenResponseBody = result
                .response
                .json()
                .await
                .map_err(|e| AAuthError::Message(e.to_string()))?;
            return Ok(TokenExchangeResult {
                auth_token: parsed.auth_token,
                expires_in: parsed.expires_in,
            });
        }

        return Err(AAuthError::Message(
            TokenExchangeError {
                status: result.response.status().as_u16(),
                aauth_error: result.error,
            }
            .to_string(),
        ));
    }

    if response.status().is_success() {
        let parsed: TokenResponseBody = response
            .json()
            .await
            .map_err(|e| AAuthError::Message(e.to_string()))?;
        return Ok(TokenExchangeResult {
            auth_token: parsed.auth_token,
            expires_in: parsed.expires_in,
        });
    }

    Err(AAuthError::Message(
        TokenExchangeError {
            status: response.status().as_u16(),
            aauth_error: None,
        }
        .to_string(),
    ))
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
        return Err(AAuthError::Message(format!(
            "Failed to fetch person server metadata: {}",
            response.status()
        )));
    }

    let metadata: PersonServerMetadata = response
        .json()
        .await
        .map_err(|e| AAuthError::Message(e.to_string()))?;
    metadata.validate().map_err(AAuthError::Message)?;
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
