use std::collections::HashMap;
use std::sync::{Arc, Mutex};

use aauth::VerifiedToken;
use aauth::error::Result;
use aauth::headers::{AAuthRequirementParams, build_aauth_requirement};
use aauth::http::{HttpClient, HttpRequest, HttpResponse};
use aauth::metadata::clear_metadata_cache;
use aauth::server::{
    InteractionManager, InteractionManagerOptions, ResourceTokenOptions, VerifyTokenOptions,
    create_resource_token, verify_token,
};
use aauth::types::{
    AgentOkResponse, AuthOkResponse, AuthServerMetadata, JwksDocument, MetadataDocument,
    RequirementLevel, TokenExchangeRequest, TokenResponseBody,
};
use async_trait::async_trait;

use aauth::{TestKeys, mint_auth_jwt};

pub struct MockServerConfig {
    pub keys: TestKeys,
    pub resource_url: String,
    pub auth_server_url: String,
    pub agent_url: String,
    pub sub: String,
    pub require_auth_token: bool,
    pub deferred_mode: bool,
    pub interaction_manager: Option<Arc<InteractionManager>>,
    pub on_token_request: Option<Arc<Mutex<Option<TokenExchangeRequest>>>>,
    pub pending_id_capture: Option<Arc<Mutex<Option<String>>>>,
}

pub struct MockServer {
    pub client: Arc<MockHttpClient>,
}

#[derive(Clone)]
pub struct MockHttpClient {
    inner: Arc<MockServerState>,
}

struct MockServerState {
    keys: TestKeys,
    resource_url: String,
    auth_server_url: String,
    agent_url: String,
    require_auth_token: bool,
    deferred_mode: bool,
    interaction_manager: Arc<Mutex<Option<Arc<InteractionManager>>>>,
    on_token_request: Option<Arc<Mutex<Option<TokenExchangeRequest>>>>,
    pending_id_capture: Option<Arc<Mutex<Option<String>>>>,
}

impl MockServer {
    pub fn new(config: MockServerConfig) -> Self {
        clear_metadata_cache();
        let interaction_manager = Arc::new(Mutex::new(config.interaction_manager.or_else(|| {
            if config.deferred_mode {
                Some(Arc::new(InteractionManager::new(
                    InteractionManagerOptions {
                        base_url: config.auth_server_url.clone(),
                        interaction_url: format!("{}/interact", config.auth_server_url),
                        pending_path: None,
                        ttl: None,
                    },
                )))
            } else {
                None
            }
        })));

        let client = Arc::new(MockHttpClient {
            inner: Arc::new(MockServerState {
                keys: config.keys,
                resource_url: config.resource_url,
                auth_server_url: config.auth_server_url,
                agent_url: config.agent_url,
                require_auth_token: config.require_auth_token,
                deferred_mode: config.deferred_mode,
                interaction_manager,
                on_token_request: config.on_token_request,
                pending_id_capture: config.pending_id_capture,
            }),
        });

        Self { client }
    }

    pub fn interaction_manager(&self) -> Option<Arc<InteractionManager>> {
        self.client
            .inner
            .interaction_manager
            .lock()
            .unwrap()
            .clone()
    }
}

#[async_trait]
impl aauth::client::HttpClientAdapter for MockHttpClient {
    async fn send(&self, request: HttpRequest) -> Result<HttpResponse> {
        self.inner.handle(request).await
    }
}

#[async_trait]
impl HttpClient for MockHttpClient {
    async fn send(
        &self,
        request: HttpRequest,
    ) -> std::result::Result<HttpResponse, aauth::error::HttpError> {
        self.inner
            .handle(request)
            .await
            .map_err(|e| aauth::error::HttpError::Request(e.to_string()))
    }
}

impl MockServerState {
    async fn handle(&self, request: HttpRequest) -> Result<HttpResponse> {
        let url = request.url.as_str();

        if url.starts_with(&self.resource_url) {
            return self.handle_resource(request).await;
        }

        if url == format!("{}/.well-known/aauth-person.json", self.auth_server_url) {
            return Ok(aauth::http::json_response(
                200,
                &AuthServerMetadata {
                    token_endpoint: format!("{}/aauth/token", self.auth_server_url),
                    jwks_uri: Some(format!("{}/jwks", self.auth_server_url)),
                },
            ));
        }

        if url == format!("{}/aauth/token", self.auth_server_url) {
            return self.handle_token_post(request).await;
        }

        if url.starts_with(&format!("{}/pending/", self.auth_server_url)) {
            return self.handle_pending(request).await;
        }

        if url == format!("{}/.well-known/aauth-agent.json", self.agent_url) {
            return Ok(aauth::http::json_response(
                200,
                &MetadataDocument {
                    jwks_uri: format!("{}/jwks", self.agent_url),
                    extra: HashMap::new(),
                },
            ));
        }

        if url == format!("{}/jwks", self.agent_url) {
            return Ok(aauth::http::json_response(
                200,
                &JwksDocument {
                    keys: self.keys.agent_root.jwk_set(),
                },
            ));
        }

        if url == format!("{}/jwks", self.auth_server_url) {
            return Ok(aauth::http::json_response(
                200,
                &JwksDocument {
                    keys: self.keys.auth_server.jwk_set(),
                },
            ));
        }

        Ok(aauth::http::empty_response(404))
    }

    async fn handle_resource(&self, request: HttpRequest) -> Result<HttpResponse> {
        let jwt = extract_signature_jwt(&request)
            .ok_or_else(|| aauth::AAuthError::Message("Missing signature-key jwt".into()))?;

        let fetcher = aauth::metadata::CachedMetadataFetcher::new(self.client_for_metadata());

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
            VerifiedToken::Auth(auth) => Ok(aauth::http::json_response(
                200,
                &AuthOkResponse {
                    status: "ok".into(),
                    user: auth.sub,
                },
            )),
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

                Ok(HttpResponse {
                    status: 401,
                    headers: HashMap::from([("AAuth-Requirement".to_string(), header)]),
                    body: b"Auth token required".to_vec(),
                })
            }
            VerifiedToken::Agent(agent) => Ok(aauth::http::json_response(
                200,
                &AgentOkResponse {
                    status: "ok".into(),
                    agent: agent.iss,
                },
            )),
        }
    }

    fn client_for_metadata(&self) -> Arc<dyn HttpClient> {
        Arc::new(MockHttpClient {
            inner: Arc::new(MockServerState {
                keys: self.keys.clone(),
                resource_url: self.resource_url.clone(),
                auth_server_url: self.auth_server_url.clone(),
                agent_url: self.agent_url.clone(),
                require_auth_token: self.require_auth_token,
                deferred_mode: self.deferred_mode,
                interaction_manager: Arc::clone(&self.interaction_manager),
                on_token_request: self.on_token_request.clone(),
                pending_id_capture: self.pending_id_capture.clone(),
            }),
        }) as Arc<dyn HttpClient>
    }

    async fn handle_token_post(&self, request: HttpRequest) -> Result<HttpResponse> {
        let body: Option<TokenExchangeRequest> = request
            .body
            .as_ref()
            .map(|b| serde_json::from_slice(b))
            .transpose()
            .map_err(|e| aauth::AAuthError::Message(e.to_string()))?;

        if let Some(capture) = &self.on_token_request {
            *capture.lock().unwrap() = body.clone();
        }

        if self.deferred_mode {
            if let Some(manager) = self.interaction_manager.lock().unwrap().clone() {
                let (headers, pending) = manager.create_pending();
                if let Some(capture) = &self.pending_id_capture {
                    *capture.lock().unwrap() = Some(pending.id.clone());
                }
                return Ok(HttpResponse {
                    status: 202,
                    headers,
                    body: Vec::new(),
                });
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

        Ok(aauth::http::json_response(
            200,
            &TokenResponseBody {
                auth_token: auth_jwt,
                expires_in: 3600,
            },
        ))
    }

    async fn handle_pending(&self, request: HttpRequest) -> Result<HttpResponse> {
        let manager = self
            .interaction_manager
            .lock()
            .unwrap()
            .clone()
            .ok_or_else(|| aauth::AAuthError::Message("no interaction manager".into()))?;

        let id = request
            .url
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
            return Ok(aauth::http::empty_response(410));
        };

        if let Some(result) = pending.result.lock().unwrap().clone() {
            match result {
                Ok(value) => {
                    manager.remove(&id);
                    return Ok(aauth::http::json_response(200, &value));
                }
                Err(err) => {
                    manager.remove(&id);
                    return Ok(HttpResponse {
                        status: 500,
                        headers: HashMap::new(),
                        body: err.into_bytes(),
                    });
                }
            }
        }

        Ok(HttpResponse {
            status: 202,
            headers: HashMap::from([
                ("Retry-After".to_string(), "0".to_string()),
                ("Cache-Control".to_string(), "no-store".to_string()),
            ]),
            body: Vec::new(),
        })
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
