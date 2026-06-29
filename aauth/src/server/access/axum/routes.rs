use axum::Json;
use axum::extract::State;
use axum::http::StatusCode;

use crate::jwt::decode_resource_token_unverified;
use crate::keys::TestKeys;
use crate::server::access::keys::mint_access_auth_jwt;
use crate::types::{
    AccessServerMetadata, JwksDocument, TokenExchangeRequest, TokenResponseBody,
};

#[derive(Clone)]
pub struct AccessServerState {
    pub keys: TestKeys,
    pub access_server_url: String,
    pub resource_url: String,
    pub access_jwks_uri: String,
}

pub async fn access_metadata_handler(
    State(state): State<AccessServerState>,
) -> Json<AccessServerMetadata> {
    Json(AccessServerMetadata {
        issuer: Some(state.access_server_url.clone()),
        token_endpoint: format!("{}/access/aauth/token", state.access_server_url),
        jwks_uri: Some(state.access_jwks_uri.clone()),
        name: None,
    })
}

pub async fn access_jwks_handler(State(state): State<AccessServerState>) -> Json<JwksDocument> {
    Json(JwksDocument {
        keys: state.keys.access_server.jwk_set(),
    })
}

pub async fn access_token_exchange_handler(
    State(state): State<AccessServerState>,
    body: Option<Json<TokenExchangeRequest>>,
) -> Result<Json<TokenResponseBody>, StatusCode> {
    let request = body.map(|Json(b)| b);
    let resource_token = request
        .as_ref()
        .map(|r| r.resource_token.as_str())
        .ok_or(StatusCode::BAD_REQUEST)?;

    let claims = decode_resource_token_unverified(resource_token).map_err(|_| StatusCode::BAD_REQUEST)?;

    let auth_jwt = mint_access_auth_jwt(
        &state.keys,
        &state.access_server_url,
        &state.resource_url,
        &claims.agent,
        Some("user-federated"),
        claims.scope.as_deref(),
    );

    Ok(Json(TokenResponseBody {
        auth_token: auth_jwt,
        expires_in: 3600,
    }))
}
