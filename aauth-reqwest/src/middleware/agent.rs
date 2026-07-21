use std::sync::Mutex;

use aauth::AgentAuthError;
use aauth::DeferredError;
use aauth::KeyMaterialProvider;
use aauth::agent::auth::{AgentAuth, AgentAuthAttempt, AgentAuthStep, AgentOptions};
use aauth::agent::resolve::{agent_jwt_from_signature_key, resolve_person_server_url};
use aauth::jwt::{ParsedToken, jwk_thumbprint};
use aauth::metadata::MetadataFetcher;
use aauth::protocol::{AAUTH_REQUIREMENT, AAuthChallenge};
use aauth::resource_verify::{verify_client_auth_token, verify_resource_challenge};
use http::Extensions;
use http::header::LOCATION;
use reqwest::{Request, Response};
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
            .map_err(|e| reqwest_middleware::Error::Middleware(anyhow::Error::from(e)))
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
                        matches!(step, AgentAuthStep::Finish)
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
