use std::net::SocketAddr;
use std::sync::Arc;

use aauth::TestKeys;
use aauth::VerifiedToken;
use aauth::metadata::{MetadataFetcher, StaticMetadataFetcher};
use aauth::server::axum::{
    AAuthLayer, AuthServerState, VerifiedAAuthToken, jwks_handler, pending_poll_handler,
    person_metadata_handler, token_exchange_handler,
};
use aauth::server::{InteractionManager, InteractionManagerOptions, ResourceTokenSigner};
use aauth::types::{AgentOkResponse, AuthOkResponse, JwksDocument, MetadataDocument};
use async_trait::async_trait;
use axum::Json;
use axum::Router;
use axum::extract::State;
use axum::routing::{get, post};
use tokio::net::TcpListener;
use tokio::task::JoinHandle;

#[derive(Debug, Clone)]
pub struct ServerConfig {
    pub require_auth_token: bool,
    pub with_auth_routes: bool,
}

impl Default for ServerConfig {
    fn default() -> Self {
        Self {
            require_auth_token: false,
            with_auth_routes: false,
        }
    }
}

pub struct SpawnedServer {
    pub addr: SocketAddr,
    pub keys: TestKeys,
    pub base_url: String,
    pub agent_url: String,
    pub auth_server_url: String,
    pub resource_url: String,
    pub handle: JoinHandle<()>,
}

pub async fn spawn_test_server(config: ServerConfig) -> SpawnedServer {
    let keys = aauth::create_test_keys();
    let listener = TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind ephemeral port");
    let addr = listener.local_addr().expect("local addr");
    let base_url = format!("http://{addr}");
    let agent_url = base_url.clone();
    let auth_server_url = base_url.clone();
    let resource_url = base_url.clone();
    let agent_jwks_uri = format!("{base_url}/agent/jwks");
    let auth_jwks_uri = format!("{base_url}/auth/jwks");

    let fetcher: Arc<DualMetadataFetcher> = Arc::new(DualMetadataFetcher {
        agent: StaticMetadataFetcher::new(agent_jwks_uri.clone(), keys.agent_root.jwk_set()),
        auth: StaticMetadataFetcher::new(auth_jwks_uri.clone(), keys.auth_server.jwk_set()),
        agent_jwks_uri: agent_jwks_uri.clone(),
        auth_jwks_uri: auth_jwks_uri.clone(),
    });

    let resource_token_signer: Arc<dyn ResourceTokenSigner> =
        Arc::new(keys.resource_token_signer());

    let aauth_layer = AAuthLayer::new(
        fetcher,
        resource_url.clone(),
        auth_server_url.clone(),
        config.require_auth_token,
        resource_token_signer,
    );

    let interaction_manager = Arc::new(InteractionManager::new(InteractionManagerOptions {
        base_url: auth_server_url.clone(),
        interaction_url: format!("{auth_server_url}/interact"),
        pending_path: None,
        ttl: None,
    }));

    let auth_state = AuthServerState {
        keys: keys.clone(),
        auth_server_url: auth_server_url.clone(),
        resource_url: resource_url.clone(),
        agent_url: agent_url.clone(),
        agent_jwks_uri: agent_jwks_uri.clone(),
        auth_jwks_uri: auth_jwks_uri.clone(),
        interaction_manager,
        deferred_mode: false,
    };

    let api = Router::new()
        .route("/api/data", get(api_data_handler))
        .route_layer(aauth_layer);

    let mut app = Router::new()
        .merge(api)
        .route("/.well-known/aauth-agent.json", get(agent_metadata_handler))
        .route("/agent/jwks", get(agent_jwks_handler));

    if config.with_auth_routes {
        app = app
            .route(
                "/.well-known/aauth-person.json",
                get(person_metadata_handler),
            )
            .route("/auth/jwks", get(jwks_handler))
            .route("/aauth/token", post(token_exchange_handler))
            .route("/pending/{id}", get(pending_poll_handler));
    }

    let app = app.with_state(auth_state);

    let handle = tokio::spawn(async move {
        axum::serve(listener, app).await.expect("serve");
    });

    SpawnedServer {
        addr,
        keys,
        base_url,
        agent_url,
        auth_server_url,
        resource_url,
        handle,
    }
}

async fn api_data_handler(token: VerifiedAAuthToken) -> Json<serde_json::Value> {
    match token.0 {
        VerifiedToken::Auth(auth) => Json(
            serde_json::to_value(AuthOkResponse {
                status: "ok".into(),
                user: auth.sub,
            })
            .expect("serialize"),
        ),
        VerifiedToken::Agent(agent) => Json(
            serde_json::to_value(AgentOkResponse {
                status: "ok".into(),
                agent: agent.iss,
            })
            .expect("serialize"),
        ),
    }
}

async fn agent_metadata_handler(State(state): State<AuthServerState>) -> Json<MetadataDocument> {
    Json(MetadataDocument {
        jwks_uri: state.agent_jwks_uri,
        extra: Default::default(),
    })
}

async fn agent_jwks_handler(State(state): State<AuthServerState>) -> Json<JwksDocument> {
    Json(JwksDocument {
        keys: state.keys.agent_root.jwk_set(),
    })
}

#[derive(Clone)]
struct DualMetadataFetcher {
    agent: StaticMetadataFetcher,
    auth: StaticMetadataFetcher,
    agent_jwks_uri: String,
    auth_jwks_uri: String,
}

#[async_trait]
impl MetadataFetcher for DualMetadataFetcher {
    async fn resolve_jwks_uri(&self, iss: &str, dwk: &str) -> aauth::Result<String> {
        let _ = iss;
        if dwk == "aauth-agent.json" {
            self.agent.resolve_jwks_uri(iss, dwk).await
        } else {
            self.auth.resolve_jwks_uri(iss, dwk).await
        }
    }

    async fn fetch_jwks(&self, jwks_uri: &str) -> aauth::Result<jsonwebtoken::jwk::JwkSet> {
        if jwks_uri == self.agent_jwks_uri {
            self.agent.fetch_jwks(jwks_uri).await
        } else if jwks_uri == self.auth_jwks_uri {
            self.auth.fetch_jwks(jwks_uri).await
        } else {
            Err(aauth::AAuthError::Token {
                code: "metadata_fetch_failed".into(),
                message: format!("unknown JWKS URI: {jwks_uri}"),
            })
        }
    }
}
