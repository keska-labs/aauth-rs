//! Demo agent issuer app (metadata + JWKS). Not part of a real resource server.

use aauth::TestKeys;
use aauth::protocol::{AgentProviderMetadata, JwksDocument};
use axum::Json;
use axum::Router;
use axum::extract::State;
use axum::routing::get;

#[derive(Clone)]
struct AgentIssuerState {
    jwks_uri: String,
    jwks: JwksDocument,
}

/// Build a minimal agent-provider origin (`/.well-known/aauth-agent.json` + `/jwks`).
pub fn agent_issuer_app(keys: &TestKeys, agent_url: &str) -> Router {
    let state = AgentIssuerState {
        jwks_uri: format!("{}/jwks", agent_url.trim_end_matches('/')),
        jwks: JwksDocument {
            keys: keys.agent_root.jwk_set(),
        },
    };
    Router::new()
        .route("/.well-known/aauth-agent.json", get(agent_metadata))
        .route("/jwks", get(agent_jwks))
        .with_state(state)
}

async fn agent_metadata(State(state): State<AgentIssuerState>) -> Json<AgentProviderMetadata> {
    Json(AgentProviderMetadata::from_jwks_uri(state.jwks_uri))
}

async fn agent_jwks(State(state): State<AgentIssuerState>) -> Json<JwksDocument> {
    Json(state.jwks.clone())
}
