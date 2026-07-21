use std::sync::Arc;

use http::HeaderMap;
use url::Url;

use crate::deferred::{DeferRequirement, ParsedDeferred, parse_deferred_response};
use crate::error::{DeferredError, MetadataError, Result, VerifyError, VerifyReason};
use crate::jwt::VerifiedToken;
use crate::metadata::MetadataFetcher;
use crate::person_server::config::PersonServerConfig;
use crate::person_server::keys::mint_person_server_signature_jwt;
use crate::protocol::{
    AccessServerMetadata, AccessTokenExchangeRequest, JwtTyp, TokenResponseBody,
};
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

impl PersonServerConfig {
    pub async fn federate_to_access_server(
        &self,
        resource_token: &str,
        agent_token: &str,
    ) -> Result<FederationOutcome> {
        let client = &self.http_client;
        let claims = crate::jwt::decode_resource_token_unverified(resource_token)?;
        let access_server_url = claims.aud.trim_end_matches('/').to_string();
        let metadata_url = format!("{access_server_url}/.well-known/aauth-access.json");
        let metadata_resp =
            client
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
        metadata.validate()?;

        let body = AccessTokenExchangeRequest {
            resource_token: resource_token.to_string(),
            agent_token: agent_token.to_string(),
            upstream_token: None,
            subagent_token: None,
        };

        let (authority, path) = url_authority_path(&metadata.token_endpoint)?;
        let body_json = serde_json::to_string(&body).map_err(DeferredError::Serialize)?;
        let mut headers = HeaderMap::new();
        headers.insert(
            http::header::CONTENT_TYPE,
            http::HeaderValue::from_static("application/json"),
        );
        apply_outbound_signature(
            &mut headers,
            "POST",
            &authority,
            &path,
            &mint_person_server_signature_jwt(&self.keys, &self.person_server_url),
            &self.person_server_signing_jwk(),
            None,
        )?;

        let mut request = client.post(&metadata.token_endpoint).body(body_json);
        for (name, value) in headers.iter() {
            request = request.header(name, value);
        }

        let response = request.send().await.map_err(|e| MetadataError::Request {
            url: metadata.token_endpoint.clone(),
            source: Box::new(e),
        })?;

        let status = response.status().as_u16();

        if status == 402 {
            return Err(DeferredError::PaymentNotRequirement.into());
        }

        if status == 202 {
            let headers = crate::http_util::response_headers_to_http(response.headers());
            let body_bytes = response.bytes().await.map_err(|e| MetadataError::Request {
                url: metadata.token_endpoint.clone(),
                source: Box::new(e),
            })?;
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
            return Err(MetadataError::HttpStatus {
                url: metadata.token_endpoint.clone(),
                status,
            }
            .into());
        }

        let token_body: TokenResponseBody =
            response.json().await.map_err(|e| MetadataError::Request {
                url: metadata.token_endpoint,
                source: Box::new(e),
            })?;

        verify_federated_auth_token(
            &token_body.auth_token,
            &access_server_url,
            &self.resource_url,
            agent_token,
            Arc::clone(&self.fetcher),
        )
        .await?;

        Ok(FederationOutcome::Complete(token_body))
    }
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
        _ => {
            return Err(VerifyError::Invalid {
                typ: JwtTyp::Agent,
                reason: VerifyReason::WrongTyp,
            }
            .into());
        }
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
        _ => {
            return Err(VerifyError::Invalid {
                typ: JwtTyp::Auth,
                reason: VerifyReason::ExpectedAuth,
            }
            .into());
        }
    };

    if auth.iss.trim_end_matches('/') != expected_iss.trim_end_matches('/') {
        return Err(VerifyError::IssMismatch.into());
    }
    if auth.aud.trim_end_matches('/') != expected_aud.trim_end_matches('/') {
        return Err(VerifyError::AudMismatch.into());
    }
    if auth.agent != agent.identifier() {
        return Err(VerifyError::AgentMismatch.into());
    }

    Ok(())
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
