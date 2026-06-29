use std::collections::HashMap;
use std::sync::{Arc, Mutex};

use aauth::InMemoryPendingStore;
use aauth::PendingOutcome;
use aauth::PendingStore;
use aauth::VerifiedToken;
use aauth::error::Result;
use aauth::headers::build_aauth_requirement;
use aauth::metadata::{MetadataFetcher, StaticMetadataFetcher};
use aauth::resolve_resource_token_audience;
use aauth::server::{
    DEFAULT_PENDING_TTL_SECS, DeferRequirement, PendingContext, PendingKind, PendingRecord,
    PendingSnapshot, PersonPendingContext, ResourceTokenOptions, VerifyTokenOptions,
    build_accepted, create_resource_token, generate_pending_id, pending_location, verify_token,
};
use aauth::types::{
    AgentOkResponse, AuthOkResponse, JwksDocument, MetadataDocument, PersonServerMetadata,
    AAuthChallenge, TokenExchangeRequest, TokenResponseBody,
};
use async_trait::async_trait;
use http::StatusCode;
use http_body_util::BodyExt;
use reqwest::{Request, Response, ResponseBuilderExt, Url};
use reqwest_middleware::{Error, Middleware, Next};

use super::client::AGENT_ID;

use aauth::{TestKeys, mint_auth_jwt};

pub struct MockTransport {
    inner: Arc<MockServerState>,
}

#[derive(Clone)]
pub struct MockServerState {
    pub keys: TestKeys,
    pub resource_url: String,
    pub person_server_url: String,
    pub agent_url: String,
    pub require_auth_token: bool,
    pub deferred_mode: bool,
    pub pending: InMemoryPendingStore,
    pub on_token_request: Option<Arc<Mutex<Option<TokenExchangeRequest>>>>,
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

        let person_metadata = format!("{}/.well-known/aauth-person.json", self.person_server_url);
        if url == person_metadata {
            let body = PersonServerMetadata {
                issuer: Some(self.person_server_url.clone()),
                token_endpoint: format!("{}/aauth/token", self.person_server_url),
                jwks_uri: Some(format!("{}/jwks", self.person_server_url)),
                name: None,
                permission_endpoint: None,
                interaction_endpoint: None,
                mission_endpoint: None,
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

        let token_endpoint = format!("{}/aauth/token", self.person_server_url);
        if url == token_endpoint {
            return self.handle_token_post(&url, req).await;
        }

        if url.starts_with(&format!("{}/pending/", self.person_server_url)) {
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

        let person_jwks = format!("{}/jwks", self.person_server_url);
        if url == person_jwks {
            let body = JwksDocument {
                keys: self.keys.person_server.jwk_set(),
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
            person: self
                .keys
                .person_metadata_fetcher(&self.person_server_url),
            resource: self.keys.resource_metadata_fetcher(&self.resource_url),
            agent_jwks_uri: format!("{}/jwks", self.agent_url),
            person_jwks_uri: format!("{}/jwks", self.person_server_url),
            resource_jwks_uri: format!("{}/jwks", self.resource_url),
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
                let audience =
                    resolve_resource_token_audience(&agent, None, Some(&self.person_server_url))
                        .map_err(|e| aauth::AAuthError::Message(e.to_string()))?;

                let resource_token = create_resource_token(
                    ResourceTokenOptions {
                        resource: self.resource_url.clone(),
                        audience,
                        agent: agent.identifier().to_string(),
                        agent_jkt: self.keys.agent_ephemeral.thumbprint().to_string(),
                        scope: None,
                        mission: None,
                        lifetime: None,
                    },
                    &signer,
                )
                .await
                .map_err(|e| aauth::AAuthError::Message(e))?;

                let header = build_aauth_requirement(&AAuthChallenge::AuthToken {
                    resource_token: resource_token.clone(),
                })?;

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
                    agent: agent.identifier().to_string(),
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
            let id = generate_pending_id();
            let interaction_url = format!("{}/interact", self.person_server_url);
            let location = pending_location(&self.person_server_url, "/pending", &id);
            let code = aauth::interaction_code::generate_code();
            let requirement = DeferRequirement::Interaction {
                url: interaction_url,
                code: code.clone(),
            };
            let exchange = body.clone().unwrap_or(TokenExchangeRequest {
                resource_token: String::new(),
                upstream_token: None,
                subagent_token: None,
                justification: None,
                localhost_callback: None,
                login_hint: None,
                tenant: None,
                domain_hint: None,
                capabilities: None,
                prompt: None,
                platform: None,
                device: None,
            });
            let record = PendingRecord::new(
                id,
                PendingKind::PersonToken,
                PendingContext::Person(PersonPendingContext {
                    person_server_url: self.person_server_url.clone(),
                    resource_url: self.resource_url.clone(),
                    agent_claims: aauth::jwt::AgentClaims {
                        iss: self.agent_url.clone(),
                        dwk: "aauth-agent.json".into(),
                        sub: AGENT_ID.into(),
                        jti: "mock".into(),
                        cnf: aauth::jwt::CnfClaim {
                            jwk: self.keys.agent_ephemeral.public_jwk(),
                        },
                        iat: 0,
                        exp: i64::MAX,
                        ps: Some(self.person_server_url.clone()),
                        parent_agent: None,
                    },
                    resource_claims: aauth::jwt::decode_resource_token_unverified(
                        &exchange.resource_token,
                    )
                    .unwrap_or_else(|_| aauth::jwt::ResourceClaims {
                        iss: self.resource_url.clone(),
                        dwk: "aauth-resource.json".into(),
                        aud: self.person_server_url.clone(),
                        jti: "mock".into(),
                        agent: AGENT_ID.into(),
                        agent_jkt: String::new(),
                        iat: 0,
                        exp: u64::MAX,
                        scope: None,
                        mission: None,
                        interaction: None,
                    }),
                    exchange_request: exchange,
                    agent_token: String::new(),
                    federation: None,
                }),
                PendingSnapshot::waiting(requirement.clone()),
                DEFAULT_PENDING_TTL_SECS,
            );
            let _ = self.pending.create(record).await;

            if let Ok(accepted) = build_accepted(&location, &requirement) {
                let mut builder = http::Response::builder()
                    .status(StatusCode::ACCEPTED)
                    .url(Url::parse(url).expect("valid url"));
                for (name, value) in accepted.headers.iter() {
                    builder = builder.header(name, value);
                }
                return Ok(Response::from(
                    builder.body(Vec::new()).expect("valid http response"),
                ));
            }
        }

        let auth_jwt = mint_auth_jwt(
            &self.keys,
            &self.person_server_url,
            &self.resource_url,
            &AGENT_ID,
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

        let Some(record) = self
            .pending
            .load(&id)
            .await
            .map_err(|e| aauth::AAuthError::Message(format!("pending load failed: {e}")))?
        else {
            return Ok(Response::from(
                http::Response::builder()
                    .status(StatusCode::GONE)
                    .url(Url::parse(url).expect("valid url"))
                    .body(Vec::new())
                    .expect("valid http response"),
            ));
        };

        if let PendingSnapshot::Complete(outcome) = &record.snapshot {
            let _ =
                self.pending.remove(&id).await.map_err(|e| {
                    aauth::AAuthError::Message(format!("pending remove failed: {e}"))
                })?;
            return match outcome {
                PendingOutcome::AuthToken(value) => Ok(Response::from(
                    http::Response::builder()
                        .status(StatusCode::OK)
                        .url(Url::parse(url).expect("valid url"))
                        .header("content-type", "application/json")
                        .body(serde_json::to_vec(value).expect("serialize json"))
                        .expect("valid http response"),
                )),
                PendingOutcome::Error(err) => Ok(Response::from(
                    http::Response::builder()
                        .status(StatusCode::FORBIDDEN)
                        .url(Url::parse(url).expect("valid url"))
                        .body(serde_json::to_vec(err).expect("serialize json"))
                        .expect("valid http response"),
                )),
                _ => Ok(Response::from(
                    http::Response::builder()
                        .status(StatusCode::OK)
                        .url(Url::parse(url).expect("valid url"))
                        .body(Vec::new())
                        .expect("valid http response"),
                )),
            };
        }

        Ok(Response::from(
            http::Response::builder()
                .status(StatusCode::ACCEPTED)
                .url(Url::parse(url).expect("valid url"))
                .header("retry-after", "0")
                .header("cache-control", "no-store")
                .body(Vec::new())
                .expect("valid http response"),
        ))
    }
}

struct DualMetadataFetcher {
    agent: StaticMetadataFetcher,
    person: StaticMetadataFetcher,
    resource: StaticMetadataFetcher,
    agent_jwks_uri: String,
    person_jwks_uri: String,
    resource_jwks_uri: String,
}

impl MockServerState {
    pub fn metadata_fetcher(&self) -> Arc<dyn MetadataFetcher> {
        Arc::new(DualMetadataFetcher {
            agent: self.keys.agent_metadata_fetcher(&self.agent_url),
            person: self
                .keys
                .person_metadata_fetcher(&self.person_server_url),
            resource: self.keys.resource_metadata_fetcher(&self.resource_url),
            agent_jwks_uri: format!("{}/jwks", self.agent_url),
            person_jwks_uri: format!("{}/jwks", self.person_server_url),
            resource_jwks_uri: format!("{}/jwks", self.resource_url),
        })
    }
}

#[async_trait]
impl MetadataFetcher for DualMetadataFetcher {
    async fn resolve_jwks_uri(&self, iss: &str, dwk: &str) -> Result<String> {
        let _ = iss;
        match dwk {
            "aauth-agent.json" => self.agent.resolve_jwks_uri(iss, dwk).await,
            "aauth-person.json" => self.person.resolve_jwks_uri(iss, dwk).await,
            "aauth-resource.json" => self.resource.resolve_jwks_uri(iss, dwk).await,
            _ => Err(aauth::AAuthError::Token {
                code: "metadata_fetch_failed".into(),
                message: format!("unknown dwk: {dwk}"),
            }),
        }
    }

    async fn fetch_jwks(&self, jwks_uri: &str) -> Result<jsonwebtoken::jwk::JwkSet> {
        if jwks_uri == self.agent_jwks_uri {
            self.agent.fetch_jwks(jwks_uri).await
        } else if jwks_uri == self.resource_jwks_uri {
            self.resource.fetch_jwks(jwks_uri).await
        } else {
            self.person.fetch_jwks(jwks_uri).await
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
