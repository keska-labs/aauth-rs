use std::collections::HashMap;

use axum::http::{HeaderMap, StatusCode};
use serde_json::Value;

use crate::headers::{AAuthRequirementParams, build_aauth_requirement};
use crate::types::{AAuthProtocolError, RequirementLevel, TokenResponseBody};

use super::types::{DeferRequirement, PendingOutcome, PendingSnapshot, PendingStatus};

pub struct AcceptedResponse {
    pub status: StatusCode,
    pub headers: HeaderMap,
    pub body: Value,
}

pub fn build_accepted(
    location: &str,
    requirement: &DeferRequirement,
) -> Result<AcceptedResponse, crate::error::AAuthError> {
    let (level, params) = requirement_to_header(requirement)?;
    let aauth_requirement = build_aauth_requirement(level, params.as_ref())?;

    let body = match requirement {
        DeferRequirement::Clarification { question, timeout } => {
            let mut obj = serde_json::json!({
                "status": "pending",
                "clarification": question,
            });
            if let Some(t) = timeout {
                obj["timeout"] = Value::from(*t);
            }
            obj
        }
        DeferRequirement::Claims { required_claims } => serde_json::json!({
            "status": "pending",
            "required_claims": required_claims,
        }),
        _ => serde_json::json!({ "status": "pending" }),
    };

    let mut headers = HeaderMap::new();
    headers.insert("Location", location.parse().expect("valid location"));
    headers.insert("Retry-After", "0".parse().expect("valid header"));
    headers.insert("Cache-Control", "no-store".parse().expect("valid header"));
    headers.insert(
        "AAuth-Requirement",
        aauth_requirement.parse().expect("valid requirement"),
    );
    headers.insert(
        "Content-Type",
        "application/json".parse().expect("valid content-type"),
    );

    Ok(AcceptedResponse {
        status: StatusCode::ACCEPTED,
        headers,
        body,
    })
}

pub fn build_payment_required_stub(location: &str) -> AcceptedResponse {
    let mut headers = HeaderMap::new();
    headers.insert("Location", location.parse().expect("valid location"));
    headers.insert(
        "Content-Type",
        "application/json".parse().expect("valid content-type"),
    );

    AcceptedResponse {
        status: StatusCode::PAYMENT_REQUIRED,
        headers,
        body: serde_json::json!({
            "status": "pending",
            "error": "payment_required",
            "error_description": "Payment required (stub — settlement not implemented)"
        }),
    }
}

pub enum PollResponse {
    Accepted {
        headers: HeaderMap,
        body: Option<Value>,
    },
    OkAuthToken(TokenResponseBody),
    OkOpaque(String),
    Error {
        status: StatusCode,
        error: AAuthProtocolError,
    },
    Gone,
}

pub fn map_snapshot_to_poll_parts(snapshot: &PendingSnapshot) -> PollResponse {
    if let Some(outcome) = &snapshot.outcome {
        return match outcome {
            PendingOutcome::AuthToken(body) => PollResponse::OkAuthToken(body.clone()),
            PendingOutcome::OpaqueAccess(token) => PollResponse::OkOpaque(token.clone()),
            PendingOutcome::Error(err) => PollResponse::Error {
                status: StatusCode::FORBIDDEN,
                error: err.clone(),
            },
        };
    }

    let mut headers = HeaderMap::new();
    headers.insert("Retry-After", "0".parse().expect("valid header"));
    headers.insert("Cache-Control", "no-store".parse().expect("valid header"));

    let body = if let Some(requirement) = &snapshot.requirement {
        let mut headers_extra = HashMap::new();
        if let Ok(AcceptedResponse {
            headers: defer_headers,
            body,
            ..
        }) = build_accepted("", requirement)
        {
            for (k, v) in defer_headers.iter() {
                headers_extra.insert(k.to_string(), v.to_str().unwrap_or("").to_string());
            }
            for (k, v) in headers_extra {
                if k != "Location" {
                    if let Ok(name) = axum::http::HeaderName::from_bytes(k.as_bytes()) {
                        if let Ok(value) = v.parse() {
                            headers.insert(name, value);
                        }
                    }
                }
            }
            Some(body)
        } else {
            None
        }
    } else {
        None
    };

    let status_body = match snapshot.status {
        PendingStatus::Pending => serde_json::json!({ "status": "pending" }),
        PendingStatus::Interacting => serde_json::json!({ "status": "interacting" }),
    };

    PollResponse::Accepted {
        headers,
        body: Some(body.unwrap_or(status_body)),
    }
}

fn requirement_to_header(
    requirement: &DeferRequirement,
) -> Result<(RequirementLevel, Option<AAuthRequirementParams<'_>>), crate::error::AAuthError> {
    match requirement {
        DeferRequirement::Interaction { url, code } => Ok((
            RequirementLevel::Interaction,
            Some(AAuthRequirementParams {
                url: Some(url),
                code: Some(code),
                resource_token: None,
            }),
        )),
        DeferRequirement::Clarification { .. } => Ok((RequirementLevel::Clarification, None)),
        DeferRequirement::Claims { .. } => Ok((RequirementLevel::Claims, None)),
        DeferRequirement::Approval => Ok((RequirementLevel::Approval, None)),
        DeferRequirement::Payment { .. } => Err(crate::error::AAuthError::Message(
            "payment defer uses 402, not AAuth-Requirement".into(),
        )),
    }
}
