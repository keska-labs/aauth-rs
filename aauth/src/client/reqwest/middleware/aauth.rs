use anyhow::anyhow;
use std::sync::{Arc, Mutex};

use http::Extensions;
use reqwest::{Request, Response};
use reqwest_middleware::{Middleware, Next, Result as MiddlewareResult};

use crate::client::injector::{AAuthClientOptions, AAuthInjector, AuthAttempt, InjectorStep};
use crate::client::reqwest::deferred::{DeferredOptions, poll_deferred_with};
use crate::client::reqwest::middleware::signing::{SigningMiddleware, sign_and_run};
use crate::client::reqwest::send::SignedSend;
use crate::client::reqwest::signed::SigningOptions;
use crate::client::reqwest::token_exchange::{TokenExchangeOptions, exchange_token_with};
use crate::client::resolve::{agent_jwt_from_signature_key, resolve_person_server_url};
use crate::error::{AAuthError, Result};
use crate::headers::parse_aauth_requirement;
use crate::types::RequirementLevel;

pub struct AAuthMiddleware {
    options: AAuthClientOptions,
    injector: Mutex<AAuthInjector>,
    signing: SigningMiddleware,
}

impl AAuthMiddleware {
    pub fn new(options: AAuthClientOptions) -> Self {
        let signing = SigningMiddleware::new(
            Arc::clone(&options.provider),
            SigningOptions {
                capabilities: options.capabilities.clone(),
                mission: options.mission.clone(),
            },
        );
        Self {
            injector: Mutex::new(AAuthInjector::from_options(&options)),
            signing,
            options,
        }
    }

    async fn send_wrapped(
        &self,
        req: Request,
        attempt: AuthAttempt,
        extensions: &mut Extensions,
        next: Next<'_>,
    ) -> Result<Response> {
        sign_and_run(&self.signing, req, attempt, extensions, next).await
    }

    async fn send_agent_signed(
        &self,
        req: Request,
        extensions: &mut Extensions,
        next: Next<'_>,
    ) -> Result<Response> {
        self.send_wrapped(req, AuthAttempt::AgentSigned, extensions, next)
            .await
    }
}

struct AgentSend<'a> {
    middleware: &'a AAuthMiddleware,
    extensions: &'a mut Extensions,
    next: Next<'a>,
}

#[async_trait::async_trait]
impl SignedSend for AgentSend<'_> {
    async fn send(&mut self, req: Request) -> Result<Response> {
        self.middleware
            .send_agent_signed(req, self.extensions, self.next.clone())
            .await
    }
}

#[async_trait::async_trait]
impl Middleware for AAuthMiddleware {
    async fn handle(
        &self,
        req: Request,
        extensions: &mut Extensions,
        next: Next<'_>,
    ) -> MiddlewareResult<Response> {
        self.handle_inner(req, extensions, next)
            .await
            .map_err(|e| reqwest_middleware::Error::Middleware(anyhow!(e.to_string())))
    }
}

impl AAuthMiddleware {
    async fn handle_inner(
        &self,
        req: Request,
        extensions: &mut Extensions,
        next: Next<'_>,
    ) -> Result<Response> {
        let origin = AAuthInjector::resource_origin(req.url().as_str())?;
        {
            let mut injector = self.injector.lock().unwrap();
            injector.seed_opaque(&origin);
        }

        loop {
            let attempt = {
                let mut injector = self.injector.lock().unwrap();
                injector.next_attempt(&origin)
            };

            let req_clone = req
                .try_clone()
                .ok_or_else(|| AAuthError::Message("request body is not cloneable".into()))?;

            let resp = self
                .send_wrapped(req_clone, attempt.clone(), extensions, next.clone())
                .await?;

            let step = {
                let mut injector = self.injector.lock().unwrap();
                injector.observe_response(&origin, &attempt, resp.status(), resp.headers())?
            };

            match step {
                InjectorStep::Finish => return Ok(resp),
                InjectorStep::PollDeferred => {
                    let (interaction_url, interaction_code) = interaction_from_response(&resp);
                    let location = location_header(&resp)?;
                    let result = poll_deferred_with(
                        DeferredOptions {
                            location_url: location,
                            interaction_url,
                            interaction_code,
                            on_interaction: self.options.on_interaction.clone(),
                            on_clarification: self.options.on_clarification.clone(),
                            max_poll_duration: self.options.max_poll_duration_secs,
                        },
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
                        matches!(step, InjectorStep::Finish)
                    };

                    if retry {
                        continue;
                    }
                    return Ok(result.response);
                }
                InjectorStep::Invalidate(_) => continue,
                InjectorStep::Continue => continue,
                InjectorStep::ExchangeToken { resource_token } => {
                    let material = self.options.provider.key_material().await?;
                    let agent_jwt = agent_jwt_from_signature_key(&material.signature_key)?;
                    let person_server_url = resolve_person_server_url(
                        self.options.person_server_url.as_deref(),
                        agent_jwt,
                    )?;

                    let capabilities = self
                        .options
                        .capabilities
                        .as_ref()
                        .map(|caps| caps.iter().map(|c| c.as_str().to_string()).collect());

                    let result = exchange_token_with(
                        TokenExchangeOptions {
                            person_server_url: person_server_url.clone(),
                            person_server_metadata: self.options.person_server_metadata.clone(),
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
                            max_poll_duration_secs: self.options.max_poll_duration_secs,
                        },
                        &mut AgentSend {
                            middleware: self,
                            extensions,
                            next: next.clone(),
                        },
                    )
                    .await?;

                    {
                        let mut injector = self.injector.lock().unwrap();
                        injector.record_auth_token(
                            &origin,
                            &person_server_url,
                            result.auth_token,
                            result.expires_in,
                            self.options.on_auth_token.as_ref(),
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
        .get("location")
        .and_then(|v| v.to_str().ok())
        .map(str::to_string)
        .ok_or_else(|| AAuthError::Message("202 response missing Location header".into()))
}

fn interaction_from_response(resp: &Response) -> (Option<String>, Option<String>) {
    let Some(header) = resp
        .headers()
        .get("aauth-requirement")
        .and_then(|v| v.to_str().ok())
    else {
        return (None, None);
    };
    if let Ok(challenge) = parse_aauth_requirement(header) {
        if challenge.requirement == RequirementLevel::Interaction {
            return (challenge.url, challenge.code);
        }
    }
    (None, None)
}
