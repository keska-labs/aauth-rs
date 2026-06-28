use std::time::{SystemTime, UNIX_EPOCH};

use jsonwebtoken::{Algorithm, Header};

use crate::jwt::ResourceClaims;
use crate::types::JwtTyp;

pub type SignFn = Box<
    dyn Fn(
            Header,
            ResourceClaims,
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
    pub mission: Option<crate::types::Mission>,
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

    let claims = ResourceClaims {
        iss: options.resource,
        dwk: "aauth-resource.json".into(),
        aud: options.auth_server,
        jti: uuid::Uuid::new_v4().to_string(),
        agent: options.agent,
        agent_jkt: options.agent_jkt,
        iat: now,
        exp: now + lifetime,
        scope: options.scope,
        mission: options.mission,
    };

    let mut header = Header::new(Algorithm::EdDSA);
    header.typ = Some(JwtTyp::Resource.as_str().into());

    sign(header, claims).await
}
