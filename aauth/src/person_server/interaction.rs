use crate::error::AAuthError;
use crate::person_server::service::PersonTokenServiceError;
use crate::protocol::{AAuthErrorCode, AAuthProtocolError, ResourceInteractionClaim};

pub(super) fn validate_interaction_url(url: &str) -> Result<(), PersonTokenServiceError> {
    let parsed = url::Url::parse(url).map_err(|e| {
        PersonTokenServiceError::Orchestration(AAuthError::Message(format!(
            "invalid interaction url: {e}"
        )))
    })?;
    if parsed.scheme() != "https" {
        return Err(PersonTokenServiceError::Orchestration(AAuthError::Message(
            "interaction url must use https".into(),
        )));
    }
    Ok(())
}

pub(super) fn build_resource_interaction_redirect(
    resource_ix: &ResourceInteractionClaim,
    callback_url: &str,
) -> Result<String, PersonTokenServiceError> {
    let mut url = url::Url::parse(&resource_ix.url).map_err(|e| {
        PersonTokenServiceError::Orchestration(AAuthError::Message(format!(
            "invalid resource interaction url: {e}"
        )))
    })?;
    url.query_pairs_mut()
        .clear()
        .append_pair("code", &resource_ix.code)
        .append_pair("callback", callback_url);
    Ok(url.to_string())
}

pub(super) fn map_interaction_callback_error(error: &str) -> AAuthProtocolError {
    let code = match error {
        "access_denied" => AAuthErrorCode::Denied,
        "user_abandoned" => AAuthErrorCode::Abandoned,
        "interaction_expired" => AAuthErrorCode::Expired,
        "server_error" | "temporarily_unavailable" => AAuthErrorCode::ServerError,
        other => AAuthErrorCode::Custom(other.to_string()),
    };
    AAuthProtocolError::with_description(code, error)
}
