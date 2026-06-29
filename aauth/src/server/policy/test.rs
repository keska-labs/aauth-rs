use crate::interaction_code::generate_code;
use crate::server::deferred::{DeferRequirement, PendingInput};
use crate::types::{AAuthErrorCode, AAuthProtocolError};

use super::access::{AccessTokenContext, AccessTokenPolicy};
use super::decision::{
    AuthGrant, PersonTokenDecision, ResourceConsentDecision, TokenPolicyDecision,
};
use super::error::PolicyError;
use super::person::{PersonTokenContext, PersonTokenPolicy};
use super::resource::{ResourceAccessContext, ResourceConsentPolicy};

#[derive(Debug, Clone, Default)]
pub struct AlwaysGrantPersonPolicy {
    pub sub: String,
}

impl AlwaysGrantPersonPolicy {
    pub fn new(sub: impl Into<String>) -> Self {
        Self { sub: sub.into() }
    }
}

#[async_trait::async_trait]
impl PersonTokenPolicy for AlwaysGrantPersonPolicy {
    async fn evaluate(&self, ctx: &PersonTokenContext) -> Result<PersonTokenDecision, PolicyError> {
        if ctx.audience_is_person_server() {
            Ok(PersonTokenDecision::Grant(AuthGrant {
                sub: self.sub.clone(),
                scope: ctx.resource_claims.scope.clone(),
            }))
        } else {
            Ok(PersonTokenDecision::Federate)
        }
    }

    async fn resume(
        &self,
        ctx: &PersonTokenContext,
        input: PendingInput,
    ) -> Result<PersonTokenDecision, PolicyError> {
        match input {
            PendingInput::InteractionCompleted | PendingInput::ClarificationResponse(_) => {
                self.evaluate(ctx).await
            }
            PendingInput::Cancelled => Ok(PersonTokenDecision::Deny(
                AAuthProtocolError::with_description(
                    AAuthErrorCode::AccessDenied,
                    "Request cancelled",
                ),
            )),
            PendingInput::ClaimsSubmission(_) => Err(PolicyError::Message(
                "claims submission not expected".into(),
            )),
        }
    }
}

#[derive(Debug, Clone)]
pub struct FixedSubPersonPolicy {
    pub sub: String,
}

#[async_trait::async_trait]
impl PersonTokenPolicy for FixedSubPersonPolicy {
    async fn evaluate(&self, ctx: &PersonTokenContext) -> Result<PersonTokenDecision, PolicyError> {
        AlwaysGrantPersonPolicy::new(&self.sub).evaluate(ctx).await
    }

    async fn resume(
        &self,
        ctx: &PersonTokenContext,
        input: PendingInput,
    ) -> Result<PersonTokenDecision, PolicyError> {
        AlwaysGrantPersonPolicy::new(&self.sub)
            .resume(ctx, input)
            .await
    }
}

#[derive(Debug, Clone, Default)]
pub struct AlwaysGrantAccessPolicy {
    pub sub: String,
}

impl AlwaysGrantAccessPolicy {
    pub fn new(sub: impl Into<String>) -> Self {
        Self { sub: sub.into() }
    }
}

#[async_trait::async_trait]
impl AccessTokenPolicy for AlwaysGrantAccessPolicy {
    async fn evaluate(&self, ctx: &AccessTokenContext) -> Result<TokenPolicyDecision, PolicyError> {
        Ok(TokenPolicyDecision::Grant(AuthGrant {
            sub: self.sub.clone(),
            scope: ctx.resource_claims.scope.clone(),
        }))
    }

    async fn resume(
        &self,
        ctx: &AccessTokenContext,
        input: PendingInput,
    ) -> Result<TokenPolicyDecision, PolicyError> {
        match input {
            PendingInput::InteractionCompleted | PendingInput::ClarificationResponse(_) => {
                self.evaluate(ctx).await
            }
            PendingInput::Cancelled => Ok(TokenPolicyDecision::Deny(
                AAuthProtocolError::with_description(
                    AAuthErrorCode::AccessDenied,
                    "Request cancelled",
                ),
            )),
            PendingInput::ClaimsSubmission(_) => self.evaluate(ctx).await,
        }
    }
}

#[derive(Debug, Clone, Default)]
pub struct AlwaysGrantResourcePolicy;

#[async_trait::async_trait]
impl ResourceConsentPolicy for AlwaysGrantResourcePolicy {
    async fn evaluate(
        &self,
        _ctx: &ResourceAccessContext,
    ) -> Result<ResourceConsentDecision, PolicyError> {
        Ok(ResourceConsentDecision::GrantOpaque)
    }

    async fn resume(
        &self,
        _ctx: &ResourceAccessContext,
        input: PendingInput,
    ) -> Result<ResourceConsentDecision, PolicyError> {
        match input {
            PendingInput::InteractionCompleted => Ok(ResourceConsentDecision::GrantOpaque),
            PendingInput::Cancelled => Ok(ResourceConsentDecision::Deny(
                AAuthProtocolError::with_description(
                    AAuthErrorCode::AccessDenied,
                    "Request cancelled",
                ),
            )),
            _ => Ok(ResourceConsentDecision::GrantOpaque),
        }
    }
}

#[derive(Debug, Clone)]
pub struct DeferInteractionResourcePolicy {
    pub interaction_url: String,
}

#[async_trait::async_trait]
impl ResourceConsentPolicy for DeferInteractionResourcePolicy {
    async fn evaluate(
        &self,
        _ctx: &ResourceAccessContext,
    ) -> Result<ResourceConsentDecision, PolicyError> {
        Ok(ResourceConsentDecision::Defer(
            DeferRequirement::Interaction {
                url: self.interaction_url.clone(),
                code: generate_code(),
            },
        ))
    }

    async fn resume(
        &self,
        _ctx: &ResourceAccessContext,
        input: PendingInput,
    ) -> Result<ResourceConsentDecision, PolicyError> {
        match input {
            PendingInput::InteractionCompleted => Ok(ResourceConsentDecision::GrantOpaque),
            PendingInput::Cancelled => Ok(ResourceConsentDecision::Deny(
                AAuthProtocolError::with_description(
                    AAuthErrorCode::AccessDenied,
                    "Request cancelled",
                ),
            )),
            _ => Ok(ResourceConsentDecision::GrantOpaque),
        }
    }
}

#[derive(Debug, Clone)]
pub struct ClarificationThenGrantPersonPolicy {
    pub sub: String,
    pub question: String,
}

#[async_trait::async_trait]
impl PersonTokenPolicy for ClarificationThenGrantPersonPolicy {
    async fn evaluate(
        &self,
        _ctx: &PersonTokenContext,
    ) -> Result<PersonTokenDecision, PolicyError> {
        Ok(PersonTokenDecision::Defer(
            DeferRequirement::Clarification {
                question: self.question.clone(),
                timeout: None,
            },
        ))
    }

    async fn resume(
        &self,
        ctx: &PersonTokenContext,
        input: PendingInput,
    ) -> Result<PersonTokenDecision, PolicyError> {
        match input {
            PendingInput::ClarificationResponse(_) | PendingInput::InteractionCompleted => {
                if ctx.audience_is_person_server() {
                    Ok(PersonTokenDecision::Grant(AuthGrant {
                        sub: self.sub.clone(),
                        scope: ctx.resource_claims.scope.clone(),
                    }))
                } else {
                    Ok(PersonTokenDecision::Federate)
                }
            }
            PendingInput::Cancelled => Ok(PersonTokenDecision::Deny(
                AAuthProtocolError::with_description(
                    AAuthErrorCode::AccessDenied,
                    "Request cancelled",
                ),
            )),
            PendingInput::ClaimsSubmission(_) => Err(PolicyError::Message(
                "claims submission not expected".into(),
            )),
        }
    }
}

#[derive(Debug, Clone)]
pub struct DeferInteractionPersonPolicy<P> {
    pub inner: P,
    pub interaction_url: String,
}

#[async_trait::async_trait]
impl<P> PersonTokenPolicy for DeferInteractionPersonPolicy<P>
where
    P: PersonTokenPolicy + Send + Sync + Clone,
{
    async fn evaluate(
        &self,
        _ctx: &PersonTokenContext,
    ) -> Result<PersonTokenDecision, PolicyError> {
        Ok(PersonTokenDecision::Defer(DeferRequirement::Interaction {
            url: self.interaction_url.clone(),
            code: generate_code(),
        }))
    }

    async fn resume(
        &self,
        ctx: &PersonTokenContext,
        input: PendingInput,
    ) -> Result<PersonTokenDecision, PolicyError> {
        self.inner.resume(ctx, input).await
    }
}

#[derive(Debug, Clone)]
pub struct ClarificationThenGrantAccessPolicy {
    pub sub: String,
    pub question: String,
}

#[async_trait::async_trait]
impl AccessTokenPolicy for ClarificationThenGrantAccessPolicy {
    async fn evaluate(
        &self,
        _ctx: &AccessTokenContext,
    ) -> Result<TokenPolicyDecision, PolicyError> {
        Ok(TokenPolicyDecision::Defer(
            DeferRequirement::Clarification {
                question: self.question.clone(),
                timeout: None,
            },
        ))
    }

    async fn resume(
        &self,
        ctx: &AccessTokenContext,
        input: PendingInput,
    ) -> Result<TokenPolicyDecision, PolicyError> {
        match input {
            PendingInput::ClarificationResponse(_) | PendingInput::InteractionCompleted => {
                Ok(TokenPolicyDecision::Grant(AuthGrant {
                    sub: self.sub.clone(),
                    scope: ctx.resource_claims.scope.clone(),
                }))
            }
            PendingInput::Cancelled => Ok(TokenPolicyDecision::Deny(
                AAuthProtocolError::with_description(
                    AAuthErrorCode::AccessDenied,
                    "Request cancelled",
                ),
            )),
            PendingInput::ClaimsSubmission(_) => Err(PolicyError::Message(
                "claims submission not expected".into(),
            )),
        }
    }
}

#[derive(Debug, Clone)]
pub struct DeferInteractionAccessPolicy<P> {
    pub inner: P,
    pub interaction_url: String,
}

#[async_trait::async_trait]
impl<P> AccessTokenPolicy for DeferInteractionAccessPolicy<P>
where
    P: AccessTokenPolicy + Send + Sync + Clone,
{
    async fn evaluate(
        &self,
        _ctx: &AccessTokenContext,
    ) -> Result<TokenPolicyDecision, PolicyError> {
        Ok(TokenPolicyDecision::Defer(DeferRequirement::Interaction {
            url: self.interaction_url.clone(),
            code: generate_code(),
        }))
    }

    async fn resume(
        &self,
        ctx: &AccessTokenContext,
        input: PendingInput,
    ) -> Result<TokenPolicyDecision, PolicyError> {
        self.inner.resume(ctx, input).await
    }
}

#[derive(Debug, Clone)]
pub struct DeferClaimsAccessPolicy {
    pub sub: String,
    pub required_claims: Vec<String>,
}

#[async_trait::async_trait]
impl AccessTokenPolicy for DeferClaimsAccessPolicy {
    async fn evaluate(
        &self,
        _ctx: &AccessTokenContext,
    ) -> Result<TokenPolicyDecision, PolicyError> {
        Ok(TokenPolicyDecision::Defer(DeferRequirement::Claims {
            required_claims: self.required_claims.clone(),
        }))
    }

    async fn resume(
        &self,
        ctx: &AccessTokenContext,
        input: PendingInput,
    ) -> Result<TokenPolicyDecision, PolicyError> {
        match input {
            PendingInput::ClaimsSubmission(_) | PendingInput::InteractionCompleted => {
                Ok(TokenPolicyDecision::Grant(AuthGrant {
                    sub: self.sub.clone(),
                    scope: ctx.resource_claims.scope.clone(),
                }))
            }
            PendingInput::Cancelled => Ok(TokenPolicyDecision::Deny(
                AAuthProtocolError::with_description(
                    AAuthErrorCode::AccessDenied,
                    "Request cancelled",
                ),
            )),
            PendingInput::ClarificationResponse(_) => {
                Err(PolicyError::Message("clarification not expected".into()))
            }
        }
    }
}

#[derive(Debug, Clone, Default)]
pub struct DeferApprovalAccessPolicy {
    pub sub: String,
}

#[async_trait::async_trait]
impl AccessTokenPolicy for DeferApprovalAccessPolicy {
    async fn evaluate(
        &self,
        _ctx: &AccessTokenContext,
    ) -> Result<TokenPolicyDecision, PolicyError> {
        Ok(TokenPolicyDecision::Defer(DeferRequirement::Approval))
    }

    async fn resume(
        &self,
        ctx: &AccessTokenContext,
        input: PendingInput,
    ) -> Result<TokenPolicyDecision, PolicyError> {
        match input {
            PendingInput::InteractionCompleted => Ok(TokenPolicyDecision::Grant(AuthGrant {
                sub: self.sub.clone(),
                scope: ctx.resource_claims.scope.clone(),
            })),
            PendingInput::Cancelled => Ok(TokenPolicyDecision::Deny(
                AAuthProtocolError::with_description(
                    AAuthErrorCode::AccessDenied,
                    "Request cancelled",
                ),
            )),
            _ => Ok(TokenPolicyDecision::Grant(AuthGrant {
                sub: self.sub.clone(),
                scope: ctx.resource_claims.scope.clone(),
            })),
        }
    }
}
