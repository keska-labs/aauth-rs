use std::collections::HashMap;
use std::sync::Arc;
use std::time::{Duration, Instant};

use crate::client::deferred::{poll_deferred, DeferredOptions, InteractionCallback};
use crate::client::signed::{sign_request_with_auth_token, HttpClientAdapter};
use crate::client::token_exchange::{exchange_token, TokenExchangeOptions};
use crate::client::{KeyMaterialProvider, SignedFetch, SignedFetchOptions};
use crate::error::{AAuthError, Result};
use crate::headers::parse_aauth_requirement;
use crate::http::{HttpRequest, HttpResponse};
use crate::types::{AuthServerMetadata, Capability, Mission, RequirementLevel};

#[derive(Clone)]
struct CachedToken {
    auth_token: String,
    expires_at: Instant,
    auth_server: String,
}

#[derive(Clone)]
struct CachedOpaque {
    token: String,
}

#[derive(Clone)]
pub struct AAuthFetchOptions {
    pub provider: Arc<dyn KeyMaterialProvider>,
    pub client: Arc<dyn HttpClientAdapter>,
    pub auth_server_url: Option<String>,
    pub auth_server_metadata: Option<AuthServerMetadata>,
    pub on_metadata: Option<Arc<dyn Fn(AuthServerMetadata) + Send + Sync>>,
    pub on_auth_token: Option<Arc<dyn Fn(String, u64) + Send + Sync>>,
    pub on_opaque_token: Option<Arc<dyn Fn(String) + Send + Sync>>,
    pub opaque_token: Option<String>,
    pub on_interaction: Option<InteractionCallback>,
    pub on_clarification: Option<crate::client::deferred::ClarificationCallback>,
    pub justification: Option<String>,
    pub login_hint: Option<String>,
    pub tenant: Option<String>,
    pub domain_hint: Option<String>,
    pub capabilities: Option<Vec<Capability>>,
    pub mission: Option<Mission>,
    pub prompt: Option<String>,
}

pub struct AAuthFetch {
    signed_fetch: SignedFetch,
    provider: Arc<dyn KeyMaterialProvider>,
    client: Arc<dyn HttpClientAdapter>,
    options: AAuthFetchOptions,
    token_cache: std::sync::Mutex<HashMap<String, CachedToken>>,
    opaque_cache: std::sync::Mutex<HashMap<String, CachedOpaque>>,
}

pub fn create_aauth_fetch(options: AAuthFetchOptions) -> AAuthFetch {
    let signed_fetch = crate::client::create_signed_fetch(
        Arc::clone(&options.client),
        Arc::clone(&options.provider),
        Some(SignedFetchOptions {
            capabilities: options.capabilities.clone(),
            mission: options.mission.clone(),
        }),
    );

    let opaque_cache = std::sync::Mutex::new(HashMap::new());
    if let Some(seed) = &options.opaque_token {
        // origin is resolved per-request
        let _ = seed;
    }

    AAuthFetch {
        signed_fetch,
        provider: options.provider.clone(),
        client: options.client.clone(),
        options,
        token_cache: std::sync::Mutex::new(HashMap::new()),
        opaque_cache,
    }
}

impl AAuthFetch {
    pub async fn fetch(&self, url: &str, mut request: HttpRequest) -> Result<HttpResponse> {
        request.url = url.to_string();
        let resource_origin = url::Url::parse(url)
            .map_err(|e| AAuthError::Message(e.to_string()))?
            .origin()
            .ascii_serialization();

        if let Some(seed) = &self.options.opaque_token {
            let mut cache = self.opaque_cache.lock().unwrap();
            cache
                .entry(resource_origin.clone())
                .or_insert(CachedOpaque {
                    token: seed.clone(),
                });
        }

        if let Some(cached) = self.find_cached_token(&resource_origin) {
            let response = self
                .fetch_with_auth_token(&request, &cached.auth_token)
                .await?;
            if response.status != 401 {
                self.cache_opaque_token(&resource_origin, &response);
                return self.handle_resource_interaction(response).await;
            }
            self.token_cache
                .lock()
                .unwrap()
                .remove(&cache_key(&resource_origin, &cached.auth_server));
        }

        let cached_opaque = {
            let cache = self.opaque_cache.lock().unwrap();
            cache.get(&resource_origin).map(|entry| entry.token.clone())
        };
        if let Some(opaque_token) = cached_opaque {
            let response = self
                .fetch_with_opaque_token(&request, &opaque_token)
                .await?;
            if response.status != 401 {
                self.cache_opaque_token(&resource_origin, &response);
                return self.handle_resource_interaction(response).await;
            }
            self.opaque_cache.lock().unwrap().remove(&resource_origin);
        }

        let response = self.signed_fetch.as_ref()(request.clone()).await?;

        if response.status == 200 {
            self.cache_opaque_token(&resource_origin, &response);
            return Ok(response);
        }

        if response.status == 401 {
            if let Some(header) = response.header("aauth-requirement") {
                let challenge = parse_aauth_requirement(header)?;
                if challenge.requirement == RequirementLevel::AuthToken {
                    if let Some(resource_token) = challenge.resource_token {
                        let auth_server_url = self
                            .options
                            .auth_server_url
                            .clone()
                            .ok_or_else(|| {
                                AAuthError::Message(
                                    "auth-token challenge received but no auth_server_url configured"
                                        .into(),
                                )
                            })?;

                        let capabilities = self
                            .options
                            .capabilities
                            .as_ref()
                            .map(|caps| caps.iter().map(|c| c.as_str().to_string()).collect());

                        let result = exchange_token(TokenExchangeOptions {
                            signed_fetch: self.signed_fetch.clone(),
                            auth_server_url: auth_server_url.clone(),
                            auth_server_metadata: self.options.auth_server_metadata.clone(),
                            on_metadata: self.options.on_metadata.clone(),
                            resource_token,
                            justification: self.options.justification.clone(),
                            localhost_callback: None,
                            login_hint: self.options.login_hint.clone(),
                            tenant: self.options.tenant.clone(),
                            domain_hint: self.options.domain_hint.clone(),
                            capabilities,
                            prompt: self.options.prompt.clone(),
                            on_interaction: self.options.on_interaction.clone(),
                            on_clarification: self.options.on_clarification.clone(),
                        })
                        .await?;

                        self.token_cache.lock().unwrap().insert(
                            cache_key(&resource_origin, &auth_server_url),
                            CachedToken {
                                auth_token: result.auth_token.clone(),
                                expires_at: Instant::now() + Duration::from_secs(result.expires_in),
                                auth_server: auth_server_url,
                            },
                        );

                        if let Some(on_auth_token) = &self.options.on_auth_token {
                            on_auth_token(result.auth_token.clone(), result.expires_in);
                        }

                        let retry = self
                            .fetch_with_auth_token(&request, &result.auth_token)
                            .await?;
                        self.cache_opaque_token(&resource_origin, &retry);
                        return self.handle_resource_interaction(retry).await;
                    }
                }
            }
            return Ok(response);
        }

        let terminal = self.handle_resource_interaction(response).await?;
        self.cache_opaque_token(&resource_origin, &terminal);
        Ok(terminal)
    }

    async fn fetch_with_auth_token(
        &self,
        request: &HttpRequest,
        auth_token: &str,
    ) -> Result<HttpResponse> {
        let mut signed = request.clone();
        let material = self.provider.key_material().await?;
        sign_request_with_auth_token(&mut signed, &material, auth_token)?;
        self.client.send(signed).await
    }

    async fn fetch_with_opaque_token(
        &self,
        request: &HttpRequest,
        opaque_token: &str,
    ) -> Result<HttpResponse> {
        let mut signed = request.clone();
        signed
            .headers
            .insert("authorization".to_string(), format!("AAuth {opaque_token}"));
        let material = self.provider.key_material().await?;
        crate::client::signed::sign_request(&mut signed, &material)?;
        self.client.send(signed).await
    }

    async fn handle_resource_interaction(&self, response: HttpResponse) -> Result<HttpResponse> {
        if response.status != 202 {
            return Ok(response);
        }
        let location = match response.header("location") {
            Some(v) => v.to_string(),
            None => return Ok(response),
        };

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
            signed_fetch: self.signed_fetch.clone(),
            location_url: location,
            interaction_url,
            interaction_code,
            on_interaction: self.options.on_interaction.clone(),
            on_clarification: self.options.on_clarification.clone(),
            max_poll_duration: None,
        })
        .await?;

        Ok(result.response)
    }

    fn find_cached_token(&self, resource_origin: &str) -> Option<CachedToken> {
        let mut cache = self.token_cache.lock().unwrap();
        let prefix = format!("{resource_origin}|");
        let key = cache.keys().find(|k| k.starts_with(&prefix))?.clone();
        let cached = cache.get(&key)?.clone();
        if cached.expires_at > Instant::now() + Duration::from_secs(60) {
            Some(cached)
        } else {
            cache.remove(&key);
            None
        }
    }

    fn cache_opaque_token(&self, resource_origin: &str, response: &HttpResponse) {
        if let Some(token) = response.header("aauth-access") {
            self.opaque_cache.lock().unwrap().insert(
                resource_origin.to_string(),
                CachedOpaque {
                    token: token.to_string(),
                },
            );
            if let Some(on_opaque) = &self.options.on_opaque_token {
                on_opaque(token.to_string());
            }
        }
    }
}

fn cache_key(resource_origin: &str, auth_server: &str) -> String {
    format!("{resource_origin}|{auth_server}")
}
