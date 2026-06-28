use std::collections::HashMap;
use std::sync::Arc;

use crate::client::SignedFetch;
use crate::client::deferred::{DeferredOptions, InteractionCallback, poll_deferred};
use crate::error::{AAuthError, Result};
use crate::headers::parse_aauth_requirement;
use crate::http::HttpRequest;
use crate::types::{
    AAuthProtocolError, AuthServerMetadata, RequirementLevel, TokenExchangeRequest,
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
    pub signed_fetch: SignedFetch,
    pub auth_server_url: String,
    pub auth_server_metadata: Option<AuthServerMetadata>,
    pub on_metadata: Option<Arc<dyn Fn(AuthServerMetadata) + Send + Sync>>,
    pub resource_token: String,
    pub justification: Option<String>,
    pub localhost_callback: Option<String>,
    pub login_hint: Option<String>,
    pub tenant: Option<String>,
    pub domain_hint: Option<String>,
    pub capabilities: Option<Vec<String>>,
    pub prompt: Option<String>,
    pub on_interaction: Option<InteractionCallback>,
    pub on_clarification: Option<crate::client::deferred::ClarificationCallback>,
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

pub async fn exchange_token(options: TokenExchangeOptions) -> Result<TokenExchangeResult> {
    let metadata = if let Some(metadata) = options.auth_server_metadata.clone() {
        metadata
    } else {
        let metadata = fetch_metadata(&options.signed_fetch, &options.auth_server_url).await?;
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
    let response = options.signed_fetch.as_ref()(HttpRequest {
        method: "POST".into(),
        url: metadata.token_endpoint.clone(),
        headers: HashMap::from([
            ("content-type".to_string(), "application/json".to_string()),
            ("prefer".to_string(), format!("wait={PREFER_WAIT}")),
        ]),
        body: Some(token_body.into_bytes()),
    })
    .await?;

    if response.status == 200 {
        let parsed: TokenResponseBody = response.json()?;
        return Ok(TokenExchangeResult {
            auth_token: parsed.auth_token,
            expires_in: parsed.expires_in,
        });
    }

    if response.status == 202 {
        let location = response
            .header("location")
            .ok_or_else(|| AAuthError::Message("202 response missing Location header".into()))?
            .to_string();

        let mut interaction_url = None;
        let mut interaction_code = None;
        if let Some(header) = response.header("aauth-requirement") {
            if let Ok(challenge) = parse_aauth_requirement(header) {
                if challenge.requirement == RequirementLevel::Interaction {
                    interaction_url = challenge.url;
                    interaction_code = challenge.code;
                }
            }
        }

        let result = poll_deferred(DeferredOptions {
            signed_fetch: options.signed_fetch.clone(),
            location_url: resolve_url(&options.auth_server_url, &location),
            interaction_url,
            interaction_code,
            on_interaction: options.on_interaction,
            on_clarification: options.on_clarification,
            max_poll_duration: None,
        })
        .await?;

        if result.response.status == 200 {
            let parsed: TokenResponseBody = result.response.json()?;
            return Ok(TokenExchangeResult {
                auth_token: parsed.auth_token,
                expires_in: parsed.expires_in,
            });
        }

        return Err(AAuthError::Message(
            TokenExchangeError {
                status: result.response.status,
                aauth_error: result.error,
            }
            .to_string(),
        ));
    }

    Err(AAuthError::Message(
        TokenExchangeError {
            status: response.status,
            aauth_error: None,
        }
        .to_string(),
    ))
}

async fn fetch_metadata(
    signed_fetch: &SignedFetch,
    auth_server_url: &str,
) -> Result<AuthServerMetadata> {
    let metadata_url = format!(
        "{}/.well-known/aauth-person.json",
        auth_server_url.trim_end_matches('/')
    );
    let response = signed_fetch.as_ref()(HttpRequest {
        method: "GET".into(),
        url: metadata_url,
        headers: HashMap::new(),
        body: None,
    })
    .await?;

    if !response.ok() {
        return Err(AAuthError::Message(format!(
            "Failed to fetch auth server metadata: {}",
            response.status
        )));
    }

    let metadata: AuthServerMetadata = response.json()?;
    if metadata.token_endpoint.is_empty() {
        return Err(AAuthError::Message(
            "Auth server metadata missing token_endpoint".into(),
        ));
    }
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
