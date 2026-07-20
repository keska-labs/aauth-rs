use std::sync::Arc;

use http::HeaderMap;
use url::Url;

use crate::deferred::{DeferRequirement, ParsedDeferred, parse_deferred_response};
use crate::error::{AAuthError, Result};
use crate::jwt::VerifiedToken;
use crate::metadata::MetadataFetcher;
use crate::person_server::config::PersonServerConfig;
use crate::person_server::keys::mint_person_server_signature_jwt;
use crate::protocol::{AccessServerMetadata, AccessTokenExchangeRequest, TokenResponseBody};
use crate::resource_verify::{VerifyTokenOptions, verify_token};
use crate::signature::apply_outbound_signature;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum FederationOutcome {
    Complete(TokenResponseBody),
    Deferred {
        requirement: DeferRequirement,
        as_pending_url: String,
        access_server_url: String,
    },
}

pub async fn federate_to_access_server(
    client: &reqwest::Client,
    config: &PersonServerConfig,
    resource_token: &str,
    agent_token: &str,
) -> Result<FederationOutcome> {
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

    let (authority, path) = url_authority_path(&metadata.token_endpoint)?;
    let body_json = serde_json::to_string(&body).map_err(|e| AAuthError::Message(e.to_string()))?;
    let mut headers = HeaderMap::new();
    headers.insert(
        http::HeaderName::from_static("content-type"),
        http::HeaderValue::from_static("application/json"),
    );
    apply_outbound_signature(
        &mut headers,
        "POST",
        &authority,
        &path,
        &mint_person_server_signature_jwt(&config.keys, &config.person_server_url),
        &config.person_server_signing_jwk(),
        None,
    )?;

    let mut request = client.post(&metadata.token_endpoint).body(body_json);
    for (name, value) in headers.iter() {
        request = request.header(name, value);
    }

    let response = request
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
        let headers = response_headers_to_http(response.headers());
        let body_bytes = response
            .bytes()
            .await
            .map_err(|e| AAuthError::Message(e.to_string()))?;
        let ParsedDeferred {
            location,
            requirement,
        } = parse_deferred_response(status, &headers, &body_bytes, &access_server_url)?;
        return Ok(FederationOutcome::Deferred {
            requirement,
            as_pending_url: location,
            access_server_url,
        });
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
        &config.resource_url,
        agent_token,
        Arc::clone(&config.fetcher),
    )
    .await?;

    Ok(FederationOutcome::Complete(token_body))
}

pub async fn verify_federated_auth_token(
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

    let agent_jkt = crate::jwt::jwk_thumbprint(&agent.cnf.jwk)?;

    let verified = verify_token(VerifyTokenOptions {
        jwt: auth_token.to_string(),
        http_signature_thumbprint: agent_jkt,
        fetcher,
    })
    .await?;

    let auth = match verified {
        VerifiedToken::Auth(c) => c,
        _ => return Err(AAuthError::Message("expected auth token from AS".into())),
    };

    if auth.iss.trim_end_matches('/') != expected_iss.trim_end_matches('/') {
        return Err(AAuthError::Message("auth token iss mismatch".into()));
    }
    if auth.aud.trim_end_matches('/') != expected_aud.trim_end_matches('/') {
        return Err(AAuthError::Message("auth token aud mismatch".into()));
    }
    if auth.agent != agent.identifier() {
        return Err(AAuthError::Message("auth token agent mismatch".into()));
    }

    Ok(())
}

fn url_authority_path(url: &str) -> Result<(String, String)> {
    let parsed = Url::parse(url).map_err(|e| AAuthError::Message(e.to_string()))?;
    let authority = parsed
        .host_str()
        .ok_or_else(|| AAuthError::Message("token endpoint missing host".into()))?
        .to_string();
    let authority = match parsed.port() {
        Some(port) => format!("{authority}:{port}"),
        None => authority,
    };
    let path = parsed.path().to_string();
    Ok((authority, path))
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
