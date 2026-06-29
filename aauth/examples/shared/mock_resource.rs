use std::sync::Arc;

use aauth::TestKeys;
use aauth::VerifiedToken;
use aauth::client::{AAuthClientOptions, AAuthMiddleware, ClientBuilder, KeyMaterialProvider};
use aauth::server::{VerifyTokenOptions, verify_token};
use aauth::types::AgentOkResponse;
use http::Extensions;
use http::StatusCode;
use reqwest::{Request, Response, ResponseBuilderExt, Url};
use reqwest_middleware::{Error, Middleware, Next};

const AGENT_URL: &str = "https://agent.example";

pub fn build_client(
    provider: Arc<dyn KeyMaterialProvider>,
    keys: TestKeys,
    resource_url: impl Into<String>,
) -> aauth::client::ClientWithMiddleware {
    let resource_url = resource_url.into();
    ClientBuilder::new(reqwest::Client::new())
        .with(AAuthMiddleware::new(AAuthClientOptions {
            provider,
            auth_server_url: None,
            auth_server_metadata: None,
            on_metadata: None,
            on_auth_token: None,
            on_opaque_token: None,
            opaque_token: None,
            on_interaction: None,
            on_clarification: None,
            justification: None,
            login_hint: None,
            tenant: None,
            domain_hint: None,
            capabilities: None,
            mission: None,
            prompt: None,
        }))
        .with(MockResourceTransport {
            keys,
            resource_url,
        })
        .build()
}

struct MockResourceTransport {
    keys: TestKeys,
    resource_url: String,
}

#[async_trait::async_trait]
impl Middleware for MockResourceTransport {
    async fn handle(
        &self,
        req: Request,
        _extensions: &mut Extensions,
        _next: Next<'_>,
    ) -> std::result::Result<Response, Error> {
        self.handle(req)
            .await
            .map_err(|e| Error::Middleware(anyhow::anyhow!(e.to_string())))
    }
}

impl MockResourceTransport {
    async fn handle(&self, req: Request) -> aauth::Result<Response> {
        let url = req.url().as_str();
        if !url.starts_with(&self.resource_url) {
            return Ok(Response::from(
                http::Response::builder()
                    .status(StatusCode::NOT_FOUND)
                    .url(Url::parse(url).expect("valid url"))
                    .body(Vec::new())
                    .expect("valid http response"),
            ));
        }

        let jwt = extract_signature_jwt(&req)
            .ok_or_else(|| aauth::AAuthError::Message("Missing signature-key jwt".into()))?;

        let fetcher = self.keys.agent_metadata_fetcher(AGENT_URL);
        let verified = verify_token(VerifyTokenOptions {
            jwt,
            http_signature_thumbprint: self.keys.agent_ephemeral.thumbprint().to_string(),
            fetcher: Arc::new(fetcher),
        })
        .await;

        let verified = match verified {
            Ok(v) => v,
            Err(e) => {
                return Ok(Response::from(
                    http::Response::builder()
                        .status(StatusCode::UNAUTHORIZED)
                        .url(Url::parse(url).expect("valid url"))
                        .body(e.to_string().into_bytes())
                        .expect("valid http response"),
                ));
            }
        };

        let body = match verified {
            VerifiedToken::Agent(agent) => AgentOkResponse {
                status: "ok".into(),
                agent: agent.iss,
            },
            VerifiedToken::Auth(_) => AgentOkResponse {
                status: "ok".into(),
                agent: AGENT_URL.into(),
            },
        };

        Ok(Response::from(
            http::Response::builder()
                .status(StatusCode::OK)
                .url(Url::parse(url).expect("valid url"))
                .header("content-type", "application/json")
                .body(serde_json::to_vec(&body).expect("serialize json"))
                .expect("valid http response"),
        ))
    }
}

fn extract_signature_jwt(req: &Request) -> Option<String> {
    let header = req
        .headers()
        .get("signature-key")
        .and_then(|v| v.to_str().ok())?;
    let start = header.find("jwt=\"")? + 5;
    let rest = &header[start..];
    let end = rest.find('"')?;
    Some(rest[..end].to_string())
}
