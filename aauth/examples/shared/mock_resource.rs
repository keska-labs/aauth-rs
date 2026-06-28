use std::collections::HashMap;
use std::sync::Arc;

use aauth::error::Result;
use aauth::http::{HttpClient, HttpRequest, HttpResponse};
use aauth::metadata::CachedMetadataFetcher;
use aauth::server::{verify_token, VerifyTokenOptions};
use aauth::types::AgentOkResponse;
use aauth::VerifiedToken;
use aauth::TestKeys;
use async_trait::async_trait;

const AGENT_URL: &str = "https://agent.example";

pub struct MockResourceClient {
    keys: TestKeys,
    resource_url: String,
}

impl MockResourceClient {
    pub fn new(keys: TestKeys, resource_url: impl Into<String>) -> Arc<Self> {
        Arc::new(Self {
            keys,
            resource_url: resource_url.into(),
        })
    }
}

#[async_trait]
impl aauth::client::HttpClientAdapter for MockResourceClient {
    async fn send(&self, request: HttpRequest) -> Result<HttpResponse> {
        self.handle(request).await
    }
}

#[async_trait]
impl HttpClient for MockResourceClient {
    async fn send(
        &self,
        request: HttpRequest,
    ) -> std::result::Result<HttpResponse, aauth::error::HttpError> {
        self.handle(request)
            .await
            .map_err(|e| aauth::error::HttpError::Request(e.to_string()))
    }
}

impl MockResourceClient {
    async fn handle(&self, request: HttpRequest) -> Result<HttpResponse> {
        if !request.url.starts_with(&self.resource_url) {
            return Ok(aauth::http::empty_response(404));
        }

        let jwt = extract_signature_jwt(&request)
            .ok_or_else(|| aauth::AAuthError::Message("Missing signature-key jwt".into()))?;

        let metadata_client = Arc::new(MetadataOnlyClient {
            keys: self.keys.clone(),
            agent_url: AGENT_URL.into(),
        }) as Arc<dyn HttpClient>;

        let fetcher = CachedMetadataFetcher::new(metadata_client);
        let verified = verify_token(VerifyTokenOptions {
            jwt,
            http_signature_thumbprint: self.keys.agent_ephemeral.thumbprint().to_string(),
            fetcher: Arc::new(fetcher),
        })
        .await;

        let verified = match verified {
            Ok(v) => v,
            Err(e) => {
                return Ok(HttpResponse {
                    status: 401,
                    headers: HashMap::new(),
                    body: e.to_string().into_bytes(),
                });
            }
        };

        match verified {
            VerifiedToken::Agent(agent) => Ok(aauth::http::json_response(
                200,
                &AgentOkResponse {
                    status: "ok".into(),
                    agent: agent.iss,
                },
            )),
            VerifiedToken::Auth(_) => Ok(aauth::http::json_response(
                200,
                &AgentOkResponse {
                    status: "ok".into(),
                    agent: AGENT_URL.into(),
                },
            )),
        }
    }
}

#[derive(Clone)]
struct MetadataOnlyClient {
    keys: TestKeys,
    agent_url: String,
}

#[async_trait]
impl HttpClient for MetadataOnlyClient {
    async fn send(
        &self,
        request: HttpRequest,
    ) -> std::result::Result<HttpResponse, aauth::error::HttpError> {
        let url = request.url.as_str();

        if url == format!("{}/.well-known/aauth-agent.json", self.agent_url) {
            return Ok(aauth::http::json_response(
                200,
                &aauth::MetadataDocument {
                    jwks_uri: format!("{}/jwks", self.agent_url),
                    extra: HashMap::new(),
                },
            ));
        }

        if url == format!("{}/jwks", self.agent_url) {
            return Ok(aauth::http::json_response(
                200,
                &self.keys.agent_root.jwk_set(),
            ));
        }

        Ok(aauth::http::empty_response(404))
    }
}

fn extract_signature_jwt(request: &HttpRequest) -> Option<String> {
    let header = request
        .headers
        .iter()
        .find(|(k, _)| k.eq_ignore_ascii_case("signature-key"))
        .map(|(_, v)| v.as_str())?;
    let start = header.find("jwt=\"")? + 5;
    let rest = &header[start..];
    let end = rest.find('"')?;
    Some(rest[..end].to_string())
}
