use std::collections::HashMap;
use std::sync::{Arc, Mutex};

use aauth::InMemoryOpaqueAccessStore;
use aauth::TestKeys;
use aauth::VerifiedToken;
use aauth::metadata::{MetadataFetcher, StaticMetadataFetcher};
use aauth::server::axum::{
    AAuthLayer, AccessServerState, PersonServerState, ResourceAccessPolicy, ResourceServerState,
    VerifiedAAuthToken, access_jwks_handler, access_metadata_handler,
    access_token_exchange_handler, pending_clarification_post_handler, pending_poll_handler,
    person_jwks_handler, person_metadata_handler, resource_pending_poll_handler,
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
    pub federated: bool,
    pub resource_managed: bool,
}

impl Default for ServerConfig {
    fn default() -> Self {
        Self {
            require_auth_token: false,
            with_auth_routes: false,
            deferred_mode: false,
            clarification_on_poll: false,
            federated: false,
            resource_managed: false,
        }
    }
}

#[allow(dead_code)]
pub struct SpawnedServer {
    pub keys: TestKeys,
    pub agent_url: String,
    pub person_server_url: String,
    pub resource_url: String,
    pub interaction_manager: Arc<InteractionManager>,
    pub resource_interaction_manager: Arc<InteractionManager>,
    pub opaque_store: Arc<InMemoryOpaqueAccessStore>,
    pub pending_id_capture: Arc<Mutex<Option<String>>>,
    pub resource_pending_id_capture: Arc<Mutex<Option<String>>>,
    handle: JoinHandle<()>,
}

impl Drop for SpawnedServer {
    fn drop(&mut self) {
        self.handle.abort();
    }
}

#[derive(Clone)]
struct TestServerState {
    person: PersonServerState,
    access: AccessServerState,
    resource: ResourceServerState,
    agent_jwks_uri: String,
}

impl FromRef<TestServerState> for PersonServerState {
    fn from_ref(input: &TestServerState) -> PersonServerState {
        input.person.clone()
    }
}

impl FromRef<TestServerState> for AccessServerState {
    fn from_ref(input: &TestServerState) -> AccessServerState {
        input.access.clone()
    }
}

impl FromRef<TestServerState> for ResourceServerState {
    fn from_ref(input: &TestServerState) -> ResourceServerState {
        input.resource.clone()
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
    let access_server_url = format!("{base_url}/as");
    let resource_url = base_url.clone();
    let agent_jwks_uri = format!("{base_url}/agent/jwks");
    let person_jwks_uri = format!("{base_url}/auth/jwks");
    let access_jwks_uri = format!("{access_server_url}/access/jwks");
    let resource_jwks_uri = format!("{base_url}/resource/jwks");

    let fetcher: Arc<TriMetadataFetcher> = Arc::new(TriMetadataFetcher {
        agent: StaticMetadataFetcher::new(agent_jwks_uri.clone(), keys.agent_root.jwk_set()),
        person: StaticMetadataFetcher::new(person_jwks_uri.clone(), keys.person_server.jwk_set()),
        access: StaticMetadataFetcher::new(access_jwks_uri.clone(), keys.access_server.jwk_set()),
        resource: StaticMetadataFetcher::new(resource_jwks_uri.clone(), keys.resource.jwk_set()),
        agent_jwks_uri: agent_jwks_uri.clone(),
        person_jwks_uri: person_jwks_uri.clone(),
        access_jwks_uri: access_jwks_uri.clone(),
        resource_jwks_uri: resource_jwks_uri.clone(),
    });

    let resource_token_signer: Arc<dyn ResourceTokenSigner> =
        Arc::new(keys.resource_token_signer());

    let opaque_store = Arc::new(InMemoryOpaqueAccessStore::new());

    let person_interaction_manager = Arc::new(InteractionManager::new(InteractionManagerOptions {
        base_url: person_server_url.clone(),
        interaction_url: format!("{person_server_url}/interact"),
        pending_path: None,
        ttl: None,
    }));

    let resource_interaction_manager =
        Arc::new(InteractionManager::new(InteractionManagerOptions {
            base_url: resource_url.clone(),
            interaction_url: format!("{resource_url}/interact"),
            pending_path: Some("/resource/pending".into()),
            ttl: None,
        }));

    let pending_id_capture = Arc::new(Mutex::new(None));
    let resource_pending_id_capture = Arc::new(Mutex::new(None));
    let clarification_state = Arc::new(Mutex::new(HashMap::new()));
    let http_client = reqwest::Client::new();

    let policy = if config.resource_managed {
        ResourceAccessPolicy::ResourceManaged {
            interaction_manager: Arc::clone(&resource_interaction_manager),
            opaque_store: Arc::clone(&opaque_store) as Arc<dyn aauth::OpaqueAccessStore>,
            pending_id_capture: Some(Arc::clone(&resource_pending_id_capture)),
        }
    } else {
        ResourceAccessPolicy::PsAsserted {
            require_auth_token: config.require_auth_token,
            access_server_url: if config.federated {
                Some(access_server_url.clone())
            } else {
                None
            },
            person_server_fallback: Some(person_server_url.clone()),
        }
    };

    let aauth_layer = AAuthLayer::new(
        Arc::clone(&fetcher) as Arc<dyn MetadataFetcher>,
        resource_url.clone(),
        policy,
        resource_token_signer,
    );

    let test_state = TestServerState {
        person: PersonServerState {
            keys: keys.clone(),
            person_server_url: person_server_url.clone(),
            resource_url: resource_url.clone(),
            agent_url: agent_url.clone(),
            person_jwks_uri: person_jwks_uri.clone(),
            interaction_manager: Arc::clone(&person_interaction_manager),
            deferred_mode: config.deferred_mode,
            pending_id_capture: Some(Arc::clone(&pending_id_capture)),
            clarification_state: if config.clarification_on_poll {
                Some(Arc::clone(&clarification_state))
            } else {
                None
            },
            clarification_prompt: config.clarification_on_poll,
            fetcher: Arc::clone(&fetcher) as Arc<dyn MetadataFetcher>,
            http_client: http_client.clone(),
        },
        access: AccessServerState {
            keys: keys.clone(),
            access_server_url: access_server_url.clone(),
            resource_url: resource_url.clone(),
            access_jwks_uri: access_jwks_uri.clone(),
        },
        resource: ResourceServerState {
            interaction_manager: Arc::clone(&resource_interaction_manager),
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

    if config.with_auth_routes || config.federated {
        let token_handler = if config.deferred_mode {
            post(token_exchange_deferred_handler)
        } else {
            post(token_exchange_handler)
        };

        app = app
            .route(
                "/.well-known/aauth-person.json",
                get(person_metadata_handler),
            )
            .route("/auth/jwks", get(person_jwks_handler))
            .route("/aauth/token", token_handler)
            .route(
                "/pending/{id}",
                get(pending_poll_handler).post(pending_clarification_post_handler),
            );
    }

    if config.federated {
        app = app
            .route(
                "/as/.well-known/aauth-access.json",
                get(access_metadata_handler),
            )
            .route("/as/access/jwks", get(access_jwks_handler))
            .route(
                "/as/access/aauth/token",
                post(access_token_exchange_handler),
            );
    }

    if config.resource_managed {
        app = app.route("/resource/pending/{id}", get(resource_pending_poll_handler));
    }

    let app = app.with_state(test_state);

    let handle = tokio::spawn(async move {
        axum::serve(listener, app).await.expect("serve");
    });

    SpawnedServer {
        keys,
        agent_url,
        person_server_url,
        resource_url,
        interaction_manager: person_interaction_manager,
        resource_interaction_manager,
        opaque_store,
        pending_id_capture,
        resource_pending_id_capture,
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

async fn agent_metadata_handler(State(state): State<TestServerState>) -> Json<MetadataDocument> {
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
struct TriMetadataFetcher {
    agent: StaticMetadataFetcher,
    person: StaticMetadataFetcher,
    access: StaticMetadataFetcher,
    resource: StaticMetadataFetcher,
    agent_jwks_uri: String,
    person_jwks_uri: String,
    access_jwks_uri: String,
    resource_jwks_uri: String,
}

#[async_trait]
impl MetadataFetcher for TriMetadataFetcher {
    async fn resolve_jwks_uri(&self, iss: &str, dwk: &str) -> aauth::Result<String> {
        let _ = iss;
        match dwk {
            "aauth-agent.json" => self.agent.resolve_jwks_uri(iss, dwk).await,
            "aauth-person.json" => self.person.resolve_jwks_uri(iss, dwk).await,
            "aauth-access.json" => self.access.resolve_jwks_uri(iss, dwk).await,
            "aauth-resource.json" => self.resource.resolve_jwks_uri(iss, dwk).await,
            _ => Err(aauth::AAuthError::Token {
                code: "metadata_fetch_failed".into(),
                message: format!("unknown dwk: {dwk}"),
            }),
        }
    }

    async fn fetch_jwks(&self, jwks_uri: &str) -> aauth::Result<jsonwebtoken::jwk::JwkSet> {
        if jwks_uri == self.agent_jwks_uri {
            self.agent.fetch_jwks(jwks_uri).await
        } else if jwks_uri == self.person_jwks_uri {
            self.person.fetch_jwks(jwks_uri).await
        } else if jwks_uri == self.access_jwks_uri {
            self.access.fetch_jwks(jwks_uri).await
        } else if jwks_uri == self.resource_jwks_uri {
            self.resource.fetch_jwks(jwks_uri).await
        } else {
            Err(aauth::AAuthError::Token {
                code: "metadata_fetch_failed".into(),
                message: format!("unknown JWKS URI: {jwks_uri}"),
            })
        }
    }
}
