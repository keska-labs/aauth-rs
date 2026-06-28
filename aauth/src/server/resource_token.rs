use std::time::{SystemTime, UNIX_EPOCH};

use serde_json::Value;

use crate::types::{JwtTyp, Mission};

pub type SignFn = Box<
    dyn Fn(
            Value,
            Value,
        )
            -> std::pin::Pin<Box<dyn std::future::Future<Output = Result<String, String>> + Send>>
        + Send
        + Sync,
>;

#[derive(Debug, Clone)]
pub struct ResourceTokenOptions {
    pub resource: String,
    pub auth_server: String,
    pub agent: String,
    pub agent_jkt: String,
    pub scope: Option<String>,
    pub mission: Option<Mission>,
    pub lifetime: Option<u64>,
}

pub async fn create_resource_token(
    options: ResourceTokenOptions,
    sign: &SignFn,
) -> Result<String, String> {
    let lifetime = options.lifetime.unwrap_or(300);
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(|e| e.to_string())?
        .as_secs();

    let mut payload = serde_json::json!({
        "iss": options.resource,
        "dwk": "aauth-resource.json",
        "aud": options.auth_server,
        "jti": uuid::Uuid::new_v4().to_string(),
        "agent": options.agent,
        "agent_jkt": options.agent_jkt,
        "iat": now,
        "exp": now + lifetime,
    });

    if let Some(scope) = options.scope {
        payload["scope"] = serde_json::json!(scope);
    }
    if let Some(mission) = options.mission {
        payload["mission"] = serde_json::json!({
            "approver": mission.approver,
            "s256": mission.s256,
        });
    }

    let header = serde_json::json!({
        "alg": "EdDSA",
        "typ": JwtTyp::Resource.as_str(),
    });

    sign(payload, header).await
}
