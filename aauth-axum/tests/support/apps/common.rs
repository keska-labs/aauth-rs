//! Shared protected API + resource discovery handlers for test app definers.

use aauth::ParsedToken;
use aauth::TestKeys;
use aauth::protocol::{
    AgentOkResponse, AuthOkResponse, JwksDocument, ResourceAccessModeWire, ResourceServerMetadata,
};
use aauth_axum::VerifiedAAuthToken;
use axum::Json;
use axum::extract::State;

#[derive(Clone)]
pub struct ResourceDiscoveryState {
    pub resource_url: String,
    pub resource_jwks: JwksDocument,
    pub access_mode: Option<ResourceAccessModeWire>,
    pub authorization_endpoint: Option<String>,
}

impl ResourceDiscoveryState {
    pub fn from_keys(keys: &TestKeys, resource_url: &str) -> Self {
        Self {
            resource_url: resource_url.to_string(),
            resource_jwks: JwksDocument {
                keys: keys.resource.jwk_set(),
            },
            access_mode: None,
            authorization_endpoint: None,
        }
    }

    pub fn with_access_mode(mut self, mode: ResourceAccessModeWire) -> Self {
        self.access_mode = Some(mode);
        self
    }

    pub fn with_resource_managed_authorize(mut self) -> Self {
        let base = self.resource_url.trim_end_matches('/');
        self.access_mode = Some(ResourceAccessModeWire::AauthAccessToken);
        self.authorization_endpoint = Some(format!("{base}/resource/authorize"));
        self
    }
}

pub async fn api_data(token: VerifiedAAuthToken) -> Json<serde_json::Value> {
    match token.0 {
        ParsedToken::Auth(auth) => Json(
            serde_json::to_value(AuthOkResponse {
                status: "ok".into(),
                user: auth.sub,
            })
            .expect("serialize"),
        ),
        ParsedToken::Agent(agent) => Json(
            serde_json::to_value(AgentOkResponse {
                status: "ok".into(),
                agent: agent.identifier().to_string(),
            })
            .expect("serialize"),
        ),
        ParsedToken::Resource(_) => Json(serde_json::json!({
            "status": "error",
            "error": "unexpected_resource_token",
        })),
    }
}

pub async fn resource_metadata(
    State(state): State<ResourceDiscoveryState>,
) -> Json<ResourceServerMetadata> {
    Json(ResourceServerMetadata {
        issuer: Some(state.resource_url.clone()),
        jwks_uri: Some(format!("{}/jwks", state.resource_url.trim_end_matches('/'))),
        access_mode: state.access_mode,
        name: Some("aauth-rs test resource".into()),
        description: None,
        logo_uri: None,
        logo_dark_uri: None,
        documentation_uri: None,
        tos_uri: None,
        policy_uri: None,
        authorization_endpoint: state.authorization_endpoint.clone(),
        login_endpoint: None,
        scope_descriptions: None,
        signature_window: None,
        additional_signature_components: None,
        revocation_endpoint: None,
        r3_vocabularies: None,
    })
}

pub async fn resource_jwks(State(state): State<ResourceDiscoveryState>) -> Json<JwksDocument> {
    Json(state.resource_jwks.clone())
}
