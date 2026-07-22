use std::sync::Mutex;

use aauth::AgentAuthError;
use aauth::DeferredError;
use aauth::KeyMaterialProvider;
use aauth::agent::auth::{AgentAuth, AgentAuthAttempt, AgentAuthStep, AgentOptions};
use aauth::agent::resolve::{agent_jwt_from_signature_key, resolve_person_server_url};
use aauth::jwt::{ParsedToken, jwk_thumbprint};
use aauth::metadata::MetadataFetcher;
use aauth::protocol::{
    AAUTH_REQUIREMENT, AAuthChallenge, AuthorizationRequest, ResourceServerMetadata,
};
use aauth::resource_verify::{verify_client_auth_token, verify_resource_challenge};
use http::Extensions;
use http::header::{CONTENT_TYPE, LOCATION};
use reqwest::{Client, Method, Request, Response};
use reqwest_middleware::{Middleware, Next, Result as MiddlewareResult};

use crate::deferred::{AgentDeferredOptions, poll_deferred_with};
use crate::error::{AgentError, Result, from_middleware_error};
use crate::middleware::signing::SigningMiddleware;
use crate::signed::SignedSend;
use crate::signed::SigningOptions;
use crate::token_exchange::{TokenExchangeOptions, exchange_token_with};

pub struct AgentMiddleware<P, F = aauth::AbsentMetadataFetcher>
where
    P: KeyMaterialProvider + Clone,
    F: MetadataFetcher + Clone,
{
    options: AgentOptions<P, F>,
    injector: Mutex<AgentAuth>,
    signing: SigningMiddleware<P>,
    /// Used for unsigned resource metadata discovery before proactive authorize.
    client: Client,
}

impl<P, F> AgentMiddleware<P, F>
where
    P: KeyMaterialProvider + Clone,
    F: MetadataFetcher + Clone,
{
    pub fn new(options: AgentOptions<P, F>) -> Self {
        let signing = SigningMiddleware::new(
            options.provider().clone(),
            SigningOptions {
                capabilities: options.capabilities().cloned(),
                mission: options.mission().cloned(),
            },
        );
        Self {
            injector: Mutex::new(AgentAuth::from_options(&options)),
            signing,
            options,
            client: Client::new(),
        }
    }
}

impl<P, F> AgentMiddleware<P, F>
where
    P: KeyMaterialProvider + Clone + Send + Sync,
    F: MetadataFetcher + Clone + Send + Sync,
{
    async fn send_wrapped(
        &self,
        req: Request,
        attempt: AgentAuthAttempt,
        extensions: &mut Extensions,
        next: Next<'_>,
    ) -> Result<Response> {
        self.signing
            .sign_and_run(req, attempt, extensions, next)
            .await
            .map_err(from_middleware_error)
    }

    async fn send_agent_signed(
        &self,
        req: Request,
        extensions: &mut Extensions,
        next: Next<'_>,
    ) -> Result<Response> {
        self.send_wrapped(req, AgentAuthAttempt::AgentSigned, extensions, next)
            .await
    }

    /// If resource metadata advertises `authorization_endpoint` and we have no opaque
    /// token yet, POST authorize once, poll if deferred, and cache any `AAuth-Access`.
    ///
    /// Spec: `#authorization-endpoint-request`, `#authorization-endpoint-responses`
    async fn try_proactive_authorize(
        &self,
        origin: &str,
        extensions: &mut Extensions,
        next: Next<'_>,
    ) -> Result<()> {
        {
            let mut injector = self.injector.lock().unwrap();
            if !injector.begin_authorize_attempt(origin) {
                return Ok(());
            }
        }

        let meta_url = format!(
            "{}/.well-known/aauth-resource.json",
            origin.trim_end_matches('/')
        );
        let Ok(resp) = self.client.get(&meta_url).send().await else {
            return Ok(());
        };
        if !resp.status().is_success() {
            return Ok(());
        }
        let Ok(meta) = resp.json::<ResourceServerMetadata>().await else {
            return Ok(());
        };
        let Some(endpoint) = meta.authorization_endpoint else {
            return Ok(());
        };

        let scope = self.options.scope().unwrap_or("").to_string();
        let body = serde_json::to_vec(&AuthorizationRequest { scope }).map_err(|e| {
            aauth::MetadataError::Decode {
                url: endpoint.clone(),
                source: e,
            }
        })?;
        let mut req = Request::new(
            Method::POST,
            reqwest::Url::parse(&endpoint).map_err(AgentAuthError::InvalidOrigin)?,
        );
        *req.body_mut() = Some(body.into());
        req.headers_mut().insert(
            CONTENT_TYPE,
            http::HeaderValue::from_static("application/json"),
        );

        let resp = self
            .send_agent_signed(req, extensions, next.clone())
            .await?;
        let step = {
            let mut injector = self.injector.lock().unwrap();
            injector.observe_response(
                origin,
                &AgentAuthAttempt::AgentSigned,
                resp.status(),
                resp.headers(),
            )?
        };

        if matches!(step, AgentAuthStep::PollDeferred) {
            let (interaction_url, interaction_code) = interaction_from_response(&resp);
            let deferred = AgentDeferredOptions::from_agent_options(
                &self.options,
                location_header(&resp)?,
                interaction_url,
                interaction_code,
            );
            let result = poll_deferred_with(
                deferred,
                &mut AgentSend {
                    middleware: self,
                    extensions,
                    next,
                },
            )
            .await?;
            let mut injector = self.injector.lock().unwrap();
            let _ = injector.observe_response(
                origin,
                &AgentAuthAttempt::AgentSigned,
                result.response.status(),
                result.response.headers(),
            )?;
        }
        Ok(())
    }
}

struct AgentSend<'a, P, F>
where
    P: KeyMaterialProvider + Clone,
    F: MetadataFetcher + Clone,
{
    middleware: &'a AgentMiddleware<P, F>,
    extensions: &'a mut Extensions,
    next: Next<'a>,
}

impl<P, F> SignedSend for AgentSend<'_, P, F>
where
    P: KeyMaterialProvider + Clone + Send + Sync,
    F: MetadataFetcher + Clone + Send + Sync,
{
    async fn send(&mut self, req: Request) -> Result<Response> {
        self.middleware
            .send_agent_signed(req, self.extensions, self.next.clone())
            .await
    }
}

#[async_trait::async_trait]
impl<P, F> Middleware for AgentMiddleware<P, F>
where
    P: KeyMaterialProvider + Clone + Send + Sync + 'static,
    F: MetadataFetcher + Clone + Send + Sync + 'static,
{
    async fn handle(
        &self,
        req: Request,
        extensions: &mut Extensions,
        next: Next<'_>,
    ) -> MiddlewareResult<Response> {
        self.handle_inner(req, extensions, next)
            .await
            .map_err(reqwest_middleware::Error::middleware)
    }
}

impl<P, F> AgentMiddleware<P, F>
where
    P: KeyMaterialProvider + Clone + Send + Sync + 'static,
    F: MetadataFetcher + Clone + Send + Sync + 'static,
{
    async fn handle_inner(
        &self,
        req: Request,
        extensions: &mut Extensions,
        next: Next<'_>,
    ) -> Result<Response> {
        let origin = AgentAuth::resource_origin(req.url().as_str())?;
        {
            let mut injector = self.injector.lock().unwrap();
            injector.seed_opaque(&origin);
        }

        self.try_proactive_authorize(&origin, extensions, next.clone())
            .await?;

        loop {
            let attempt = {
                let mut injector = self.injector.lock().unwrap();
                injector.next_attempt(&origin)
            };

            let req_clone = req.try_clone().ok_or(AgentError::BodyNotCloneable)?;

            let resp = self
                .send_wrapped(req_clone, attempt.clone(), extensions, next.clone())
                .await?;

            let step = {
                let mut injector = self.injector.lock().unwrap();
                injector.observe_response(&origin, &attempt, resp.status(), resp.headers())?
            };

            match step {
                AgentAuthStep::Finish => return Ok(resp),
                AgentAuthStep::RetryWithOpaque => continue,
                AgentAuthStep::PollDeferred => {
                    let (interaction_url, interaction_code) = interaction_from_response(&resp);
                    let location = location_header(&resp)?;
                    let deferred = AgentDeferredOptions::from_agent_options(
                        &self.options,
                        location,
                        interaction_url,
                        interaction_code,
                    );
                    let result = poll_deferred_with(
                        deferred,
                        &mut AgentSend {
                            middleware: self,
                            extensions,
                            next: next.clone(),
                        },
                    )
                    .await?;

                    let retry = {
                        let mut injector = self.injector.lock().unwrap();
                        let step = injector.observe_response(
                            &origin,
                            &attempt,
                            result.response.status(),
                            result.response.headers(),
                        )?;
                        matches!(step, AgentAuthStep::Finish | AgentAuthStep::RetryWithOpaque)
                    };

                    if retry {
                        continue;
                    }
                    return Ok(result.response);
                }
                AgentAuthStep::Invalidate(_) => continue,
                AgentAuthStep::ExchangeToken { resource_token } => {
                    let material = self.options.provider().key_material().await?;
                    let agent_jwt = agent_jwt_from_signature_key(&material.signature_key)?;
                    let agent_sub = match ParsedToken::parse(agent_jwt)? {
                        ParsedToken::Agent(agent) => agent.identifier().to_string(),
                        _ => {
                            return Err(AgentAuthError::ExpectedAgentJwt.into());
                        }
                    };
                    let agent_jkt = jwk_thumbprint(&material.signing_jwk.public_jwk())?;

                    let resource_claims = verify_resource_challenge(
                        &resource_token,
                        &origin,
                        &agent_sub,
                        &agent_jkt,
                        self.options.metadata_fetcher(),
                    )
                    .await?;

                    let person_server_url =
                        resolve_person_server_url(self.options.person_server_url(), agent_jwt)?;

                    let exchange = TokenExchangeOptions::from_agent_options(
                        &self.options,
                        person_server_url.clone(),
                        resource_token,
                    );

                    let result = exchange_token_with(
                        exchange,
                        &mut AgentSend {
                            middleware: self,
                            extensions,
                            next: next.clone(),
                        },
                    )
                    .await?;

                    verify_client_auth_token(
                        &result.auth_token,
                        &origin,
                        &resource_claims.aud,
                        &agent_sub,
                        &agent_jkt,
                        self.options.metadata_fetcher(),
                        self.options.verify_auth_signature(),
                    )
                    .await?;

                    {
                        let mut injector = self.injector.lock().unwrap();
                        injector.record_auth_token(
                            &origin,
                            &person_server_url,
                            result.auth_token,
                            result.expires_in,
                            self.options.on_auth_token(),
                        );
                    }
                    continue;
                }
            }
        }
    }
}

fn location_header(resp: &Response) -> Result<String> {
    resp.headers()
        .get(LOCATION)
        .and_then(|v| v.to_str().ok())
        .map(str::to_string)
        .ok_or_else(|| DeferredError::MissingLocation.into())
}

fn interaction_from_response(resp: &Response) -> (Option<String>, Option<String>) {
    let Some(header) = resp
        .headers()
        .get(AAUTH_REQUIREMENT)
        .and_then(|v| v.to_str().ok())
    else {
        return (None, None);
    };
    if let Ok(AAuthChallenge::Interaction { url, code }) = AAuthChallenge::from_header(header) {
        return (Some(url), Some(code));
    }
    (None, None)
}
