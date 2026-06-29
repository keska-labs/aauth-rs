use std::sync::Arc;

use crate::error::{AAuthError, Result};
use crate::jwt::VerifiedToken;
use crate::metadata::MetadataFetcher;
use crate::server::person::keys::AuthJwtMinter;
use crate::types::{AccessServerMetadata, AccessTokenExchangeRequest, TokenResponseBody};

#[derive(Clone)]
pub struct FederationConfig {
    pub fetcher: Arc<dyn MetadataFetcher>,
}

pub async fn federate_to_access_server<M: AuthJwtMinter>(
    client: &reqwest::Client,
    fetcher: Arc<dyn MetadataFetcher>,
    _minter: &M,
    _person_server_url: &str,
    resource_url: &str,
    resource_token: &str,
    agent_token: &str,
) -> Result<TokenResponseBody> {
    let claims = crate::jwt::decode_resource_token_unverified(resource_token)?;
    let access_server_url = claims.aud.trim_end_matches('/').to_string();
    let metadata_url = format!("{access_server_url}/.well-known/aauth-access.json");
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

    let body = AccessTokenExchangeRequest {
        resource_token: resource_token.to_string(),
        agent_token: agent_token.to_string(),
        upstream_token: None,
        subagent_token: None,
    };

    let response = client
        .post(&metadata.token_endpoint)
        .header("content-type", "application/json")
        .json(&body)
        .send()
        .await
        .map_err(|e| AAuthError::Message(e.to_string()))?;

    let status = response.status().as_u16();

    if status == 402 {
        return Err(AAuthError::Message(
            "Access server payment required (402 stub — settlement not implemented)".into(),
        ));
    }

    if status == 202 {
        return Err(AAuthError::Message(
            "Access server deferred response during federation (not yet fully handled)".into(),
        ));
    }

    if !response.status().is_success() {
        return Err(AAuthError::Message(format!(
            "Access server token exchange failed: {}",
            response.status()
        )));
    }

    let token_body: TokenResponseBody = response
        .json()
        .await
        .map_err(|e| AAuthError::Message(e.to_string()))?;

    verify_federated_auth_token(
        &token_body.auth_token,
        &access_server_url,
        resource_url,
        agent_token,
        fetcher,
    )
    .await?;

    Ok(token_body)
}

async fn verify_federated_auth_token(
    auth_token: &str,
    expected_iss: &str,
    expected_aud: &str,
    agent_token: &str,
    fetcher: Arc<dyn MetadataFetcher>,
) -> Result<()> {
    let agent = match VerifiedToken::decode_unverified(agent_token)? {
        VerifiedToken::Agent(c) => c,
        _ => return Err(AAuthError::Message("expected agent token".into())),
    };

    let auth = match VerifiedToken::decode_unverified(auth_token)? {
        VerifiedToken::Auth(c) => c,
        _ => return Err(AAuthError::Message("expected auth token from AS".into())),
    };

    if auth.iss.trim_end_matches('/') != expected_iss.trim_end_matches('/') {
        return Err(AAuthError::Message("auth token iss mismatch".into()));
    }
    if auth.aud.trim_end_matches('/') != expected_aud.trim_end_matches('/') {
        return Err(AAuthError::Message("auth token aud mismatch".into()));
    }
    if auth.agent != agent.iss {
        return Err(AAuthError::Message("auth token agent mismatch".into()));
    }

    let _ = fetcher;
    let _ = auth;
    Ok(())
}

/// Legacy helper used by integration tests.
pub async fn fulfill_token_exchange(
    keys: &crate::keys::TestKeys,
    person_server_url: &str,
    resource_url: &str,
    agent_url: &str,
    resource_token: &str,
    fetcher: Arc<dyn MetadataFetcher>,
    client: &reqwest::Client,
) -> Result<TokenResponseBody> {
    use crate::server::person::keys::AuthJwtMinter;

    let minter = keys.auth_jwt_minter();
    let claims = crate::server::resource::verify_resource_token(
        crate::server::resource::VerifyResourceTokenOptions {
            jwt: resource_token.to_string(),
            expected_agent: Some(agent_url.to_string()),
            expected_agent_jkt: None,
            fetcher: Arc::clone(&fetcher),
        },
    )
    .await?;

    let ps = person_server_url.trim_end_matches('/');
    let aud = claims.aud.trim_end_matches('/');

    if aud == ps {
        let auth_jwt = minter.mint_auth_jwt(
            person_server_url,
            resource_url,
            agent_url,
            Some("user-123"),
            claims.scope.as_deref(),
        );
        return Ok(TokenResponseBody {
            auth_token: auth_jwt,
            expires_in: 3600,
        });
    }

    let agent_jwt = minter.mint_auth_jwt(
        agent_url,
        agent_url,
        agent_url,
        None,
        None,
    );
    let _ = agent_jwt;

    federate_to_access_server(
        client,
        fetcher,
        &minter,
        person_server_url,
        resource_url,
        resource_token,
        &crate::mint_agent_jwt(keys, agent_url, agent_url, Some(person_server_url)),
    )
    .await
}
