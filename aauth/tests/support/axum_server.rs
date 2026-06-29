use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::{Arc, Mutex};

use aauth::TestKeys;
use aauth::VerifiedToken;
use aauth::metadata::{MetadataFetcher, StaticMetadataFetcher};
use aauth::server::axum::{
    AAuthLayer, PersonServerState, VerifiedAAuthToken, pending_clarification_post_handler,
    pending_poll_handler, person_jwks_handler, person_metadata_handler,
    token_exchange_deferred_handler, token_exchange_handler,
};
use aauth::server::{InteractionManager, InteractionManagerOptions, ResourceTokenSigner};
use aauth::types::{AgentOkResponse, AuthOkResponse, JwksDocument, MetadataDocument};
use async_trait::async_trait;
use axum::Json;
use axum::Router;
use axum::extract::{FromRef, State};
use axum::routing::{get, post};
use tokio::net::TcpListener;
use tokio::task::JoinHandle;

#[derive(Debug, Clone)]
pub struct ServerConfig {
    pub require_auth_token: bool,
    pub with_auth_routes: bool,
    pub deferred_mode: bool,
    pub clarification_on_poll: bool,
}

impl Default for ServerConfig {
    fn default() -> Self {
        Self {
            require_auth_token: false,
            with_auth_routes: false,
            deferred_mode: false,
            clarification_on_poll: false,
        }
    }
}

pub struct SpawnedServer {
    pub addr: SocketAddr,
    pub keys: TestKeys,
    pub agent_url: String,
    pub person_server_url: String,
    pub resource_url: String,
    pub interaction_manager: Arc<InteractionManager>,
    pub pending_id_capture: Arc<Mutex<Option<String>>>,
    handle: JoinHandle<()>,
}

impl Drop for SpawnedServer {
    fn drop(&mut self) {
        self.handle.abort();
    }
}

/// Combined test harness state: person-server routes plus agent well-known endpoints.
#[derive(Clone)]
struct TestServerState {
    person: PersonServerState,
    agent_jwks_uri: String,
}

impl FromRef<TestServerState> for PersonServerState {
    fn from_ref(input: &TestServerState) -> PersonServerState {
        input.person.clone()
    }
}

pub async fn spawn_test_server(config: ServerConfig) -> SpawnedServer {
    let keys = aauth::create_test_keys();
    let listener = TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind ephemeral port");
    let addr = listener.local_addr().expect("local addr");
    let base_url = format!("http://{addr}");
    let agent_url = base_url.clone();
    let person_server_url = base_url.clone();
    let resource_url = base_url.clone();
    let agent_jwks_uri = format!("{base_url}/agent/jwks");
    let person_jwks_uri = format!("{base_url}/auth/jwks");

    let fetcher: Arc<DualMetadataFetcher> = Arc::new(DualMetadataFetcher {
        agent: StaticMetadataFetcher::new(agent_jwks_uri.clone(), keys.agent_root.jwk_set()),
        person: StaticMetadataFetcher::new(person_jwks_uri.clone(), keys.person_server.jwk_set()),
        agent_jwks_uri: agent_jwks_uri.clone(),
        person_jwks_uri: person_jwks_uri.clone(),
    });

    let resource_token_signer: Arc<dyn ResourceTokenSigner> =
        Arc::new(keys.resource_token_signer());

    let aauth_layer = AAuthLayer::new(
        fetcher,
        resource_url.clone(),
        person_server_url.clone(),
        config.require_auth_token,
        resource_token_signer,
    );

    let interaction_manager = Arc::new(InteractionManager::new(InteractionManagerOptions {
        base_url: person_server_url.clone(),
        interaction_url: format!("{person_server_url}/interact"),
        pending_path: None,
        ttl: None,
    }));

    let pending_id_capture = Arc::new(Mutex::new(None));
    let clarification_state = Arc::new(Mutex::new(HashMap::new()));

    let test_state = TestServerState {
        person: PersonServerState {
            keys: keys.clone(),
            person_server_url: person_server_url.clone(),
            resource_url: resource_url.clone(),
            agent_url: agent_url.clone(),
            person_jwks_uri: person_jwks_uri.clone(),
            interaction_manager: Arc::clone(&interaction_manager),
            deferred_mode: config.deferred_mode,
            pending_id_capture: Some(Arc::clone(&pending_id_capture)),
            clarification_state: if config.clarification_on_poll {
                Some(Arc::clone(&clarification_state))
            } else {
                None
            },
            clarification_prompt: config.clarification_on_poll,
        },
        agent_jwks_uri: agent_jwks_uri.clone(),
    };

    let api = Router::new()
        .route("/api/data", get(api_data_handler))
        .route_layer(aauth_layer);

    let mut app = Router::new()
        .merge(api)
        .route("/.well-known/aauth-agent.json", get(agent_metadata_handler))
        .route("/agent/jwks", get(agent_jwks_handler));

    if config.with_auth_routes {
        let token_handler = if config.deferred_mode {
            post(token_exchange_deferred_handler)
        } else {
            post(token_exchange_handler)
        };

        app = app
            .route("/.well-known/aauth-person.json", get(person_metadata_handler))
            .route("/auth/jwks", get(person_jwks_handler))
            .route("/aauth/token", token_handler)
            .route(
                "/pending/{id}",
                get(pending_poll_handler).post(pending_clarification_post_handler),
            );
    }

    let app = app.with_state(test_state);

    let handle = tokio::spawn(async move {
        axum::serve(listener, app).await.expect("serve");
    });

    SpawnedServer {
        addr,
        keys,
        agent_url,
        person_server_url,
        resource_url,
        interaction_manager,
        pending_id_capture,
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

async fn agent_metadata_handler(
    State(state): State<TestServerState>,
) -> Json<MetadataDocument> {
    Json(MetadataDocument {
        jwks_uri: state.agent_jwks_uri,
        extra: Default::default(),
    })
}

async fn agent_jwks_handler(State(state): State<TestServerState>) -> Json<JwksDocument> {
    Json(JwksDocument {
        keys: state.person.keys.agent_root.jwk_set(),
    })
}

#[derive(Clone)]
struct DualMetadataFetcher {
    agent: StaticMetadataFetcher,
    person: StaticMetadataFetcher,
    agent_jwks_uri: String,
    person_jwks_uri: String,
}

#[async_trait]
impl MetadataFetcher for DualMetadataFetcher {
    async fn resolve_jwks_uri(&self, iss: &str, dwk: &str) -> aauth::Result<String> {
        let _ = iss;
        if dwk == "aauth-agent.json" {
            self.agent.resolve_jwks_uri(iss, dwk).await
        } else {
            self.person.resolve_jwks_uri(iss, dwk).await
        }
    }

    async fn fetch_jwks(&self, jwks_uri: &str) -> aauth::Result<jsonwebtoken::jwk::JwkSet> {
        if jwks_uri == self.agent_jwks_uri {
            self.agent.fetch_jwks(jwks_uri).await
        } else if jwks_uri == self.person_jwks_uri {
            self.person.fetch_jwks(jwks_uri).await
        } else {
            Err(aauth::AAuthError::Token {
                code: "metadata_fetch_failed".into(),
                message: format!("unknown JWKS URI: {jwks_uri}"),
            })
        }
    }
}
