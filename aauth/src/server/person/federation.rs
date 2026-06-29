use std::sync::Arc;

use crate::error::{AAuthError, Result};
use crate::keys::TestKeys;
use crate::metadata::MetadataFetcher;
use crate::server::person::keys::mint_auth_jwt;
use crate::server::resource::{VerifyResourceTokenOptions, verify_resource_token};
use crate::types::{AccessServerMetadata, TokenExchangeRequest, TokenResponseBody};

fn normalize_url(url: &str) -> String {
    url.trim_end_matches('/').to_string()
}

/// Verify a resource token and return an auth token, federating to the AS when `aud` != PS.
pub async fn fulfill_token_exchange(
    keys: &TestKeys,
    person_server_url: &str,
    resource_url: &str,
    agent_url: &str,
    resource_token: &str,
    fetcher: Arc<dyn MetadataFetcher>,
    client: &reqwest::Client,
) -> Result<TokenResponseBody> {
    let claims = verify_resource_token(VerifyResourceTokenOptions {
        jwt: resource_token.to_string(),
        expected_agent: Some(agent_url.to_string()),
        expected_agent_jkt: None,
        fetcher: Arc::clone(&fetcher),
    })
    .await?;

    let ps = normalize_url(person_server_url);
    let aud = normalize_url(&claims.aud);

    if aud == ps {
        let auth_jwt = mint_auth_jwt(
            keys,
            person_server_url,
            resource_url,
            &claims.agent,
            Some("user-123"),
            claims.scope.as_deref(),
        );
        return Ok(TokenResponseBody {
            auth_token: auth_jwt,
            expires_in: 3600,
        });
    }

    federate_to_access_server(client, &claims.aud, resource_token).await
}

async fn federate_to_access_server(
    client: &reqwest::Client,
    access_server_url: &str,
    resource_token: &str,
) -> Result<TokenResponseBody> {
    let base = access_server_url.trim_end_matches('/');
    let metadata_url = format!("{base}/.well-known/aauth-access.json");
    let metadata_resp = client
        .get(&metadata_url)
        .send()
        .await
        .map_err(|e| AAuthError::Message(e.to_string()))?;

    if !metadata_resp.status().is_success() {
        return Err(AAuthError::Message(format!(
            "Failed to fetch access server metadata: {}",
            metadata_resp.status()
        )));
    }

    let metadata: AccessServerMetadata = metadata_resp
        .json()
        .await
        .map_err(|e| AAuthError::Message(e.to_string()))?;
    metadata.validate().map_err(AAuthError::Message)?;

    let body = TokenExchangeRequest {
        resource_token: resource_token.to_string(),
        justification: None,
        localhost_callback: None,
        login_hint: None,
        tenant: None,
        domain_hint: None,
        capabilities: None,
        prompt: None,
    };

    let response = client
        .post(&metadata.token_endpoint)
        .header("content-type", "application/json")
        .json(&body)
        .send()
        .await
        .map_err(|e| AAuthError::Message(e.to_string()))?;

    if !response.status().is_success() {
        return Err(AAuthError::Message(format!(
            "Access server token exchange failed: {}",
            response.status()
        )));
    }

    response
        .json()
        .await
        .map_err(|e| AAuthError::Message(e.to_string()))
}
