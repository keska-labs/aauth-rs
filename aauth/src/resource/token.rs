use std::time::{SystemTime, UNIX_EPOCH};

use jsonwebtoken::{Algorithm, Header};

use crate::jwt::ResourceClaims;
use crate::protocol::JwtTyp;
use crate::resource::keys::ResourceTokenSigner;

#[derive(Debug, Clone)]
pub struct ResourceTokenOptions {
    pub resource: String,
    pub audience: String,
    pub agent: String,
    pub agent_jkt: String,
    pub scope: Option<String>,
    pub mission: Option<crate::protocol::Mission>,
    pub lifetime: Option<u64>,
}

pub async fn create_resource_token(
    options: ResourceTokenOptions,
    signer: &dyn ResourceTokenSigner,
) -> Result<String, String> {
    let lifetime = options.lifetime.unwrap_or(300);
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(|e| e.to_string())?
        .as_secs();

    let claims = ResourceClaims {
        iss: options.resource,
        dwk: "aauth-resource.json".into(),
        aud: options.audience,
        jti: uuid::Uuid::new_v4().to_string(),
        agent: options.agent,
        agent_jkt: options.agent_jkt,
        iat: now,
        exp: now + lifetime,
        scope: options.scope,
        mission: options.mission,
        interaction: None,
    };

    let mut header = Header::new(Algorithm::EdDSA);
    header.typ = Some(JwtTyp::Resource.as_str().into());

    signer.sign_resource_token(header, claims).await
}
