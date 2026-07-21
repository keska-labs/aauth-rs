use aauth::DeferRequirement;
use aauth::PendingInput;
use aauth::generate_code;
use aauth::protocol::{AAuthErrorCode, AAuthProtocolError};

#[cfg(feature = "access-server")]
use aauth::AccessTokenContext;
#[cfg(feature = "person-server")]
use aauth::PersonTokenContext;
#[cfg(feature = "resource")]
use aauth::ResourceAccessContext;

#[cfg(feature = "access-server")]
use crate::AccessTokenDecision;
#[cfg(feature = "access-server")]
use crate::AccessTokenPolicy;
use crate::AuthGrant;
#[cfg(feature = "person-server")]
use crate::PersonTokenDecision;
#[cfg(feature = "person-server")]
use crate::PersonTokenPolicy;
use crate::PolicyError;
#[cfg(feature = "resource")]
use crate::ResourceConsentDecision;
#[cfg(feature = "resource")]
use crate::ResourceConsentPolicy;

#[cfg(feature = "person-server")]
#[derive(Debug, Clone, Default)]
pub struct AlwaysGrantPersonPolicy {
    pub sub: String,
}

#[cfg(feature = "person-server")]
impl AlwaysGrantPersonPolicy {
    pub fn new(sub: impl Into<String>) -> Self {
        Self { sub: sub.into() }
    }
}

#[cfg(feature = "person-server")]
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
            PendingInput::UpdatedToken(_) => self.evaluate(ctx).await,
        }
    }
}

#[cfg(feature = "access-server")]
#[derive(Debug, Clone, Default)]
pub struct AlwaysGrantAccessPolicy {
    pub sub: String,
}

#[cfg(feature = "access-server")]
impl AlwaysGrantAccessPolicy {
    pub fn new(sub: impl Into<String>) -> Self {
        Self { sub: sub.into() }
    }
}

#[cfg(feature = "access-server")]
impl AccessTokenPolicy for AlwaysGrantAccessPolicy {
    async fn evaluate(&self, ctx: &AccessTokenContext) -> Result<AccessTokenDecision, PolicyError> {
        Ok(AccessTokenDecision::Grant(AuthGrant {
            sub: self.sub.clone(),
            scope: ctx.resource_claims.scope.clone(),
        }))
    }

    async fn resume(
        &self,
        ctx: &AccessTokenContext,
        input: PendingInput,
    ) -> Result<AccessTokenDecision, PolicyError> {
        match input {
            PendingInput::InteractionCompleted | PendingInput::ClarificationResponse(_) => {
                self.evaluate(ctx).await
            }
            PendingInput::Cancelled => Ok(AccessTokenDecision::Deny(
                AAuthProtocolError::with_description(
                    AAuthErrorCode::AccessDenied,
                    "Request cancelled",
                ),
            )),
            PendingInput::ClaimsSubmission(_) => self.evaluate(ctx).await,
            PendingInput::UpdatedToken(_) => self.evaluate(ctx).await,
        }
    }
}

#[cfg(feature = "resource")]
#[derive(Debug, Clone, Default)]
pub struct AlwaysGrantResourcePolicy;

#[cfg(feature = "resource")]
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

#[cfg(feature = "resource")]
#[derive(Debug, Clone)]
pub struct DeferInteractionResourcePolicy {
    pub interaction_url: String,
}

#[cfg(feature = "resource")]
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

#[cfg(feature = "person-server")]
#[derive(Debug, Clone)]
pub struct ClarificationThenGrantPersonPolicy {
    pub sub: String,
    pub question: String,
}

#[cfg(feature = "person-server")]
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
            PendingInput::UpdatedToken(_) => {
                if ctx.audience_is_person_server() {
                    Ok(PersonTokenDecision::Grant(AuthGrant {
                        sub: self.sub.clone(),
                        scope: ctx.resource_claims.scope.clone(),
                    }))
                } else {
                    Ok(PersonTokenDecision::Federate)
                }
            }
        }
    }
}

#[cfg(feature = "person-server")]
#[derive(Debug, Clone)]
pub struct DeferInteractionPersonPolicy<P> {
    pub inner: P,
    pub interaction_url: String,
}

#[cfg(feature = "person-server")]
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

#[cfg(feature = "access-server")]
#[derive(Debug, Clone)]
pub struct ClarificationThenGrantAccessPolicy {
    pub sub: String,
    pub question: String,
}

#[cfg(feature = "access-server")]
impl AccessTokenPolicy for ClarificationThenGrantAccessPolicy {
    async fn evaluate(
        &self,
        _ctx: &AccessTokenContext,
    ) -> Result<AccessTokenDecision, PolicyError> {
        Ok(AccessTokenDecision::Defer(
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
    ) -> Result<AccessTokenDecision, PolicyError> {
        match input {
            PendingInput::ClarificationResponse(_) | PendingInput::InteractionCompleted => {
                Ok(AccessTokenDecision::Grant(AuthGrant {
                    sub: self.sub.clone(),
                    scope: ctx.resource_claims.scope.clone(),
                }))
            }
            PendingInput::Cancelled => Ok(AccessTokenDecision::Deny(
                AAuthProtocolError::with_description(
                    AAuthErrorCode::AccessDenied,
                    "Request cancelled",
                ),
            )),
            PendingInput::ClaimsSubmission(_) => Err(PolicyError::Message(
                "claims submission not expected".into(),
            )),
            PendingInput::UpdatedToken(_) => Ok(AccessTokenDecision::Grant(AuthGrant {
                sub: self.sub.clone(),
                scope: ctx.resource_claims.scope.clone(),
            })),
        }
    }
}

#[cfg(feature = "access-server")]
#[derive(Debug, Clone)]
pub struct DeferInteractionAccessPolicy<P> {
    pub inner: P,
    pub interaction_url: String,
}

#[cfg(feature = "access-server")]
impl<P> AccessTokenPolicy for DeferInteractionAccessPolicy<P>
where
    P: AccessTokenPolicy + Send + Sync + Clone,
{
    async fn evaluate(
        &self,
        _ctx: &AccessTokenContext,
    ) -> Result<AccessTokenDecision, PolicyError> {
        Ok(AccessTokenDecision::Defer(DeferRequirement::Interaction {
            url: self.interaction_url.clone(),
            code: generate_code(),
        }))
    }

    async fn resume(
        &self,
        ctx: &AccessTokenContext,
        input: PendingInput,
    ) -> Result<AccessTokenDecision, PolicyError> {
        self.inner.resume(ctx, input).await
    }
}

#[cfg(feature = "access-server")]
#[derive(Debug, Clone)]
pub struct DeferClaimsAccessPolicy {
    pub sub: String,
    pub required_claims: Vec<String>,
}

#[cfg(feature = "access-server")]
impl AccessTokenPolicy for DeferClaimsAccessPolicy {
    async fn evaluate(
        &self,
        _ctx: &AccessTokenContext,
    ) -> Result<AccessTokenDecision, PolicyError> {
        Ok(AccessTokenDecision::Defer(DeferRequirement::Claims {
            required_claims: self.required_claims.clone(),
        }))
    }

    async fn resume(
        &self,
        ctx: &AccessTokenContext,
        input: PendingInput,
    ) -> Result<AccessTokenDecision, PolicyError> {
        match input {
            PendingInput::ClaimsSubmission(_)
            | PendingInput::InteractionCompleted
            | PendingInput::UpdatedToken(_) => Ok(AccessTokenDecision::Grant(AuthGrant {
                sub: self.sub.clone(),
                scope: ctx.resource_claims.scope.clone(),
            })),
            PendingInput::Cancelled => Ok(AccessTokenDecision::Deny(
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

#[cfg(feature = "access-server")]
#[derive(Debug, Clone, Default)]
pub struct DeferApprovalAccessPolicy {
    pub sub: String,
}

#[cfg(feature = "access-server")]
impl AccessTokenPolicy for DeferApprovalAccessPolicy {
    async fn evaluate(
        &self,
        _ctx: &AccessTokenContext,
    ) -> Result<AccessTokenDecision, PolicyError> {
        Ok(AccessTokenDecision::Defer(DeferRequirement::Approval))
    }

    async fn resume(
        &self,
        ctx: &AccessTokenContext,
        input: PendingInput,
    ) -> Result<AccessTokenDecision, PolicyError> {
        match input {
            PendingInput::InteractionCompleted => Ok(AccessTokenDecision::Grant(AuthGrant {
                sub: self.sub.clone(),
                scope: ctx.resource_claims.scope.clone(),
            })),
            PendingInput::Cancelled => Ok(AccessTokenDecision::Deny(
                AAuthProtocolError::with_description(
                    AAuthErrorCode::AccessDenied,
                    "Request cancelled",
                ),
            )),
            _ => Ok(AccessTokenDecision::Grant(AuthGrant {
                sub: self.sub.clone(),
                scope: ctx.resource_claims.scope.clone(),
            })),
        }
    }
}
