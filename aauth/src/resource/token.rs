use std::time::{SystemTime, UNIX_EPOCH};

use jsonwebtoken::{Algorithm, Header};

use crate::error::ResourceTokenError;
use crate::jwt::ResourceClaims;
use crate::protocol::{JwtTyp, Mission, ResourceInteractionClaim};
use crate::resource::keys::ResourceTokenSigner;

#[derive(Debug, Clone)]
pub struct ResourceTokenOptions {
    pub resource: String,
    pub audience: String,
    pub agent: String,
    pub agent_jkt: String,
    pub scope: Option<String>,
    pub mission: Option<Mission>,
    pub lifetime: Option<u64>,
    pub interaction: Option<ResourceInteractionClaim>,
}

impl ResourceTokenOptions {
    pub async fn sign(
        self,
        signer: &dyn ResourceTokenSigner,
    ) -> Result<String, ResourceTokenError> {
        let lifetime = self.lifetime.unwrap_or(300);
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_err(ResourceTokenError::SystemTime)?
            .as_secs();

        let claims = ResourceClaims {
            iss: self.resource,
            dwk: "aauth-resource.json".into(),
            aud: self.audience,
            jti: uuid::Uuid::new_v4().to_string(),
            agent: self.agent,
            agent_jkt: self.agent_jkt,
            iat: now,
            exp: now + lifetime,
            scope: self.scope,
            mission: self.mission,
            interaction: self.interaction,
        };

        let mut header = Header::new(Algorithm::EdDSA);
        header.typ = Some(JwtTyp::Resource.as_str().into());

        signer.sign_resource_token(header, claims).await
    }
}
