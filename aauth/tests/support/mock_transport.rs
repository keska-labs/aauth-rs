use std::collections::HashMap;
use std::sync::{Arc, Mutex};

use aauth::VerifiedToken;
use aauth::error::Result;
use aauth::headers::{AAuthRequirementParams, build_aauth_requirement};
use aauth::metadata::{MetadataFetcher, StaticMetadataFetcher};
use aauth::server::{
    InteractionManager, ResourceTokenOptions, VerifyTokenOptions, create_resource_token,
    verify_token,
};
use aauth::types::{
    AgentOkResponse, AuthOkResponse, AuthServerMetadata, JwksDocument, MetadataDocument,
    RequirementLevel, TokenExchangeRequest, TokenResponseBody,
};
use async_trait::async_trait;
use http::StatusCode;
use http_body_util::BodyExt;
use reqwest::{Request, Response, ResponseBuilderExt, Url};
use reqwest_middleware::{Error, Middleware, Next};

use aauth::{TestKeys, mint_auth_jwt};

pub struct MockTransport {
    inner: Arc<MockServerState>,
}

#[derive(Clone)]
pub struct MockServerState {
    pub keys: TestKeys,
    pub resource_url: String,
    pub auth_server_url: String,
    pub agent_url: String,
    pub require_auth_token: bool,
    pub deferred_mode: bool,
    pub interaction_manager: Arc<Mutex<Option<Arc<InteractionManager>>>>,
    pub on_token_request: Option<Arc<Mutex<Option<TokenExchangeRequest>>>>,
    pub pending_id_capture: Option<Arc<Mutex<Option<String>>>>,
}

impl MockTransport {
    pub fn new(state: Arc<MockServerState>) -> Self {
        Self { inner: state }
    }
}

#[async_trait::async_trait]
impl Middleware for MockTransport {
    async fn handle(
        &self,
        req: Request,
        _extensions: &mut http::Extensions,
        _next: Next<'_>,
    ) -> std::result::Result<Response, Error> {
        self.inner
            .handle(req)
            .await
            .map_err(|e| Error::Middleware(anyhow::anyhow!(e.to_string())))
    }
}

impl MockServerState {
    async fn handle(&self, req: Request) -> Result<Response> {
        let url = req.url().as_str().to_string();

        if url.starts_with(&self.resource_url) {
            return self.handle_resource(&url, req).await;
        }

        let person_metadata = format!("{}/.well-known/aauth-person.json", self.auth_server_url);
        if url == person_metadata {
            let body = AuthServerMetadata {
                token_endpoint: format!("{}/aauth/token", self.auth_server_url),
                jwks_uri: Some(format!("{}/jwks", self.auth_server_url)),
            };
            return Ok(Response::from(
                http::Response::builder()
                    .status(StatusCode::OK)
                    .url(Url::parse(&url).expect("valid url"))
                    .header("content-type", "application/json")
                    .body(serde_json::to_vec(&body).expect("serialize json"))
                    .expect("valid http response"),
            ));
        }

        let token_endpoint = format!("{}/aauth/token", self.auth_server_url);
        if url == token_endpoint {
            return self.handle_token_post(&url, req).await;
        }

        if url.starts_with(&format!("{}/pending/", self.auth_server_url)) {
            return self.handle_pending(&url).await;
        }

        let agent_metadata = format!("{}/.well-known/aauth-agent.json", self.agent_url);
        if url == agent_metadata {
            let body = MetadataDocument {
                jwks_uri: format!("{}/jwks", self.agent_url),
                extra: HashMap::new(),
            };
            return Ok(Response::from(
                http::Response::builder()
                    .status(StatusCode::OK)
                    .url(Url::parse(&url).expect("valid url"))
                    .header("content-type", "application/json")
                    .body(serde_json::to_vec(&body).expect("serialize json"))
                    .expect("valid http response"),
            ));
        }

        let agent_jwks = format!("{}/jwks", self.agent_url);
        if url == agent_jwks {
            let body = JwksDocument {
                keys: self.keys.agent_root.jwk_set(),
            };
            return Ok(Response::from(
                http::Response::builder()
                    .status(StatusCode::OK)
                    .url(Url::parse(&url).expect("valid url"))
                    .header("content-type", "application/json")
                    .body(serde_json::to_vec(&body).expect("serialize json"))
                    .expect("valid http response"),
            ));
        }

        let auth_jwks = format!("{}/jwks", self.auth_server_url);
        if url == auth_jwks {
            let body = JwksDocument {
                keys: self.keys.auth_server.jwk_set(),
            };
            return Ok(Response::from(
                http::Response::builder()
                    .status(StatusCode::OK)
                    .url(Url::parse(&url).expect("valid url"))
                    .header("content-type", "application/json")
                    .body(serde_json::to_vec(&body).expect("serialize json"))
                    .expect("valid http response"),
            ));
        }

        Ok(Response::from(
            http::Response::builder()
                .status(StatusCode::NOT_FOUND)
                .url(Url::parse(&url).expect("valid url"))
                .body(Vec::new())
                .expect("valid http response"),
        ))
    }

    async fn handle_resource(&self, url: &str, req: Request) -> Result<Response> {
        let jwt = extract_signature_jwt(&req)
            .ok_or_else(|| aauth::AAuthError::Message("Missing signature-key jwt".into()))?;

        let fetcher = Arc::new(DualMetadataFetcher {
            agent: self.keys.agent_metadata_fetcher(&self.agent_url),
            auth: self.keys.auth_metadata_fetcher(&self.auth_server_url),
            agent_jwks_uri: format!("{}/jwks", self.agent_url),
            auth_jwks_uri: format!("{}/jwks", self.auth_server_url),
        });

        let verified = verify_token(VerifyTokenOptions {
            jwt,
            http_signature_thumbprint: self.keys.agent_ephemeral.thumbprint().to_string(),
            fetcher,
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

        match verified {
            VerifiedToken::Auth(auth) => {
                let body = AuthOkResponse {
                    status: "ok".into(),
                    user: auth.sub,
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
            VerifiedToken::Agent(agent) if self.require_auth_token => {
                let signer = self.keys.resource_token_signer();
                let resource_token = create_resource_token(
                    ResourceTokenOptions {
                        resource: self.resource_url.clone(),
                        auth_server: self.auth_server_url.clone(),
                        agent: agent.iss.clone(),
                        agent_jkt: self.keys.agent_ephemeral.thumbprint().to_string(),
                        scope: None,
                        mission: None,
                        lifetime: None,
                    },
                    &signer,
                )
                .await
                .map_err(|e| aauth::AAuthError::Message(e))?;

                let header = build_aauth_requirement(
                    RequirementLevel::AuthToken,
                    Some(&AAuthRequirementParams {
                        resource_token: Some(&resource_token),
                        ..Default::default()
                    }),
                )?;

                Ok(Response::from(
                    http::Response::builder()
                        .status(StatusCode::UNAUTHORIZED)
                        .url(Url::parse(url).expect("valid url"))
                        .header("AAuth-Requirement", header)
                        .body(b"Auth token required".to_vec())
                        .expect("valid http response"),
                ))
            }
            VerifiedToken::Agent(agent) => {
                let body = AgentOkResponse {
                    status: "ok".into(),
                    agent: agent.iss,
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
    }

    async fn handle_token_post(&self, url: &str, mut req: Request) -> Result<Response> {
        let body: Option<TokenExchangeRequest> = match req.body_mut().take() {
            Some(body) => {
                let bytes = body
                    .collect()
                    .await
                    .map_err(|e| aauth::AAuthError::Message(e.to_string()))?
                    .to_bytes();
                if bytes.is_empty() {
                    None
                } else {
                    Some(
                        serde_json::from_slice(&bytes)
                            .map_err(|e| aauth::AAuthError::Message(e.to_string()))?,
                    )
                }
            }
            None => None,
        };

        if let Some(capture) = &self.on_token_request {
            *capture.lock().unwrap() = body.clone();
        }

        if self.deferred_mode {
            if let Some(manager) = self.interaction_manager.lock().unwrap().clone() {
                let (headers, pending) = manager.create_pending();
                if let Some(capture) = &self.pending_id_capture {
                    *capture.lock().unwrap() = Some(pending.id.clone());
                }
                let mut builder = http::Response::builder()
                    .status(StatusCode::ACCEPTED)
                    .url(Url::parse(url).expect("valid url"));
                for (name, value) in headers {
                    builder = builder.header(name, value);
                }
                return Ok(Response::from(
                    builder.body(Vec::new()).expect("valid http response"),
                ));
            }
        }

        let auth_jwt = mint_auth_jwt(
            &self.keys,
            &self.auth_server_url,
            &self.resource_url,
            &self.agent_url,
            Some("user-123"),
            None,
        );

        let body = TokenResponseBody {
            auth_token: auth_jwt,
            expires_in: 3600,
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

    async fn handle_pending(&self, url: &str) -> Result<Response> {
        let manager = self
            .interaction_manager
            .lock()
            .unwrap()
            .clone()
            .ok_or_else(|| aauth::AAuthError::Message("no interaction manager".into()))?;

        let id = url
            .split("/pending/")
            .nth(1)
            .unwrap_or_default()
            .split('?')
            .next()
            .unwrap_or_default()
            .split('#')
            .next()
            .unwrap_or_default()
            .to_string();

        let Some(pending) = manager.get_pending(&id) else {
            return Ok(Response::from(
                http::Response::builder()
                    .status(StatusCode::GONE)
                    .url(Url::parse(url).expect("valid url"))
                    .body(Vec::new())
                    .expect("valid http response"),
            ));
        };

        if let Some(result) = pending.result.lock().unwrap().clone() {
            match result {
                Ok(value) => {
                    manager.remove(&id);
                    return Ok(Response::from(
                        http::Response::builder()
                            .status(StatusCode::OK)
                            .url(Url::parse(url).expect("valid url"))
                            .header("content-type", "application/json")
                            .body(serde_json::to_vec(&value).expect("serialize json"))
                            .expect("valid http response"),
                    ));
                }
                Err(err) => {
                    manager.remove(&id);
                    return Ok(Response::from(
                        http::Response::builder()
                            .status(StatusCode::INTERNAL_SERVER_ERROR)
                            .url(Url::parse(url).expect("valid url"))
                            .body(err.into_bytes())
                            .expect("valid http response"),
                    ));
                }
            }
        }

        Ok(Response::from(
            http::Response::builder()
                .status(StatusCode::ACCEPTED)
                .url(Url::parse(url).expect("valid url"))
                .header("Retry-After", "0")
                .header("Cache-Control", "no-store")
                .body(Vec::new())
                .expect("valid http response"),
        ))
    }
}

struct DualMetadataFetcher {
    agent: StaticMetadataFetcher,
    auth: StaticMetadataFetcher,
    agent_jwks_uri: String,
    auth_jwks_uri: String,
}

#[async_trait]
impl MetadataFetcher for DualMetadataFetcher {
    async fn resolve_jwks_uri(&self, iss: &str, dwk: &str) -> Result<String> {
        if dwk == "aauth-agent.json" {
            self.agent.resolve_jwks_uri(iss, dwk).await
        } else {
            self.auth.resolve_jwks_uri(iss, dwk).await
        }
    }

    async fn fetch_jwks(&self, jwks_uri: &str) -> Result<jsonwebtoken::jwk::JwkSet> {
        if jwks_uri == self.agent_jwks_uri {
            self.agent.fetch_jwks(jwks_uri).await
        } else {
            self.auth.fetch_jwks(jwks_uri).await
        }
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
