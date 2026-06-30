use std::sync::Arc;

use aauth::InMemoryAccessPendingStore;
use aauth::InMemoryOpaqueAccessStore;
use aauth::InMemoryPersonPendingStore;
use aauth::InMemoryResourcePendingStore;
use aauth::OpaqueAccessStore;
use aauth::PendingOutcome;
use aauth::PendingStore;
use aauth::TestKeys;
use aauth::VerifiedToken;
use aauth::access_server::keys::TestAccessAuthJwtMinter;
use aauth::metadata::{MetadataFetcher, StaticMetadataFetcher};
use aauth::person_server::keys::TestAuthJwtMinter;
use aauth::resource::{PolicyResourceAccessService, ResourceAccessConfig};
use aauth::server_axum::{
    AccessServerConfig, AccessServerState, PersonServerConfig, PersonServerState,
    ResourceAuthLayer, ResourceServerState, VerifiedAAuthToken, access_jwks_handler,
    access_metadata_handler, access_pending_poll_handler, access_pending_post_handler,
    access_token_exchange_handler, pending_poll_handler, pending_post_handler, person_jwks_handler,
    person_metadata_handler, resource_pending_poll_handler, token_exchange_handler,
};
use aauth::types::{AgentOkResponse, AuthOkResponse, JwksDocument, MetadataDocument};
use aauth::{
    AlwaysGrantPersonPolicy, ClarificationThenGrantPersonPolicy, DeferInteractionAccessPolicy,
    DeferInteractionPersonPolicy, DeferInteractionResourcePolicy, ResourceAccessMode,
    ResourceTokenSigner,
};
use async_trait::async_trait;
use axum::Json;
use axum::Router;
use axum::extract::{FromRef, State};
use axum::routing::{get, post};
use tokio::net::TcpListener;
use tokio::task::JoinHandle;

#[path = "harness_policy.rs"]
mod harness_policy;
use harness_policy::HarnessPersonPolicy;

#[path = "harness_access_policy.rs"]
mod harness_access_policy;
use harness_access_policy::HarnessAccessPolicy;

use super::timeout::TEST_POLL_MAX_SECS;

#[derive(Debug, Clone)]
pub struct ServerConfig {
    pub require_auth_token: bool,
    pub with_auth_routes: bool,
    pub deferred_mode: bool,
    pub clarification_on_poll: bool,
    pub federated: bool,
    pub as_deferred_mode: bool,
    pub as_clarification: bool,
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
            as_deferred_mode: false,
            as_clarification: false,
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
    pub metadata_fetcher: Arc<dyn MetadataFetcher>,
    pub person_pending: InMemoryPersonPendingStore,
    pub access_pending: InMemoryAccessPendingStore,
    pub resource_pending: InMemoryResourcePendingStore,
    pub opaque_store: InMemoryOpaqueAccessStore,
    handle: JoinHandle<()>,
}

impl SpawnedServer {
    pub async fn resolve_person_pending(&self, auth_token: &str) {
        if let Some(id) = self.person_pending.last_created.lock().unwrap().clone() {
            let _ = self
                .person_pending
                .complete(
                    &id,
                    PendingOutcome::AuthToken(aauth::types::TokenResponseBody {
                        auth_token: auth_token.to_string(),
                        expires_in: 3600,
                    }),
                )
                .await;
        }
    }

    pub async fn resolve_resource_pending(&self, agent_id: &str) {
        if let Some(id) = self.resource_pending.last_created.lock().unwrap().clone() {
            let opaque = self.opaque_store.issue(agent_id);
            let _ = self
                .resource_pending
                .complete(&id, PendingOutcome::OpaqueAccess(opaque))
                .await;
        }
    }
}

impl Drop for SpawnedServer {
    fn drop(&mut self) {
        self.handle.abort();
    }
}

type TestPersonState = PersonServerState<
    aauth::person_server::PolicyPersonTokenService<
        HarnessPersonPolicy,
        InMemoryPersonPendingStore,
        TestAuthJwtMinter,
    >,
>;
type TestAccessState = AccessServerState<
    aauth::access_server::PolicyAccessTokenService<
        HarnessAccessPolicy,
        InMemoryAccessPendingStore,
        TestAccessAuthJwtMinter,
    >,
>;
type TestResourceService = PolicyResourceAccessService<
    DeferInteractionResourcePolicy,
    InMemoryResourcePendingStore,
    InMemoryOpaqueAccessStore,
>;
type TestResourceState = ResourceServerState<TestResourceService>;

#[derive(Clone)]
struct TestServerState {
    person: TestPersonState,
    access: TestAccessState,
    resource: TestResourceState,
    agent_jwks_uri: String,
}

impl FromRef<TestServerState> for TestPersonState {
    fn from_ref(input: &TestServerState) -> TestPersonState {
        input.person.clone()
    }
}

impl FromRef<TestServerState> for TestAccessState {
    fn from_ref(input: &TestServerState) -> TestAccessState {
        input.access.clone()
    }
}

impl FromRef<TestServerState> for TestResourceState {
    fn from_ref(input: &TestServerState) -> TestResourceState {
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

    let opaque_store = InMemoryOpaqueAccessStore::new();
    let person_pending = InMemoryPersonPendingStore::new();
    let resource_pending = InMemoryResourcePendingStore::new();
    let http_client = reqwest::Client::new();

    let access_pending = InMemoryAccessPendingStore::new();

    let person_policy = if config.clarification_on_poll {
        HarnessPersonPolicy::Clarify(ClarificationThenGrantPersonPolicy {
            sub: "user-clarified".into(),
            question: "What is your purpose?".into(),
        })
    } else if config.deferred_mode {
        HarnessPersonPolicy::Defer(DeferInteractionPersonPolicy {
            inner: AlwaysGrantPersonPolicy::new("user-deferred"),
            interaction_url: format!("{person_server_url}/interact"),
        })
    } else {
        HarnessPersonPolicy::Grant(AlwaysGrantPersonPolicy::new("user-123"))
    };

    let access_policy = if config.federated && config.as_clarification {
        HarnessAccessPolicy::Clarify(aauth::ClarificationThenGrantAccessPolicy {
            sub: "user-federated".into(),
            question: "What is your purpose?".into(),
        })
    } else if config.federated && config.as_deferred_mode {
        HarnessAccessPolicy::Defer(DeferInteractionAccessPolicy {
            inner: aauth::AlwaysGrantAccessPolicy::new("user-federated"),
            interaction_url: format!("{access_server_url}/interact"),
        })
    } else {
        HarnessAccessPolicy::Grant(aauth::AlwaysGrantAccessPolicy::new("user-federated"))
    };

    let resource_service = PolicyResourceAccessService::new(
        DeferInteractionResourcePolicy {
            interaction_url: format!("{resource_url}/interact"),
        },
        resource_pending.clone(),
        opaque_store.clone(),
        ResourceAccessConfig {
            interaction_url: format!("{resource_url}/interact"),
            pending_base_url: resource_url.clone(),
            pending_path: "/resource/pending".into(),
            pending_ttl_secs: aauth::DEFAULT_PENDING_TTL_SECS,
        },
    );

    let mode = if config.resource_managed {
        ResourceAccessMode::ResourceManaged {
            service: resource_service.clone(),
        }
    } else {
        ResourceAccessMode::PsAsserted {
            require_auth_token: config.require_auth_token,
            access_server_url: if config.federated {
                Some(access_server_url.clone())
            } else {
                None
            },
            person_server_fallback: Some(person_server_url.clone()),
        }
    };

    let resource_auth_layer = ResourceAuthLayer::new(
        Arc::clone(&fetcher) as Arc<dyn MetadataFetcher>,
        resource_url.clone(),
        mode,
        resource_token_signer,
    );

    let test_state = TestServerState {
        person: PersonServerState::from_policy(
            person_policy,
            person_pending.clone(),
            keys.auth_jwt_minter(),
            PersonServerConfig {
                keys: keys.clone(),
                person_server_url: person_server_url.clone(),
                resource_url: resource_url.clone(),
                agent_url: agent_url.clone(),
                person_jwks_uri: person_jwks_uri.clone(),
                interaction_url: format!("{person_server_url}/interact"),
                pending_base_url: person_server_url.clone(),
                pending_path: "/pending".into(),
                pending_ttl_secs: aauth::DEFAULT_PENDING_TTL_SECS,
                fetcher: Arc::clone(&fetcher) as Arc<dyn MetadataFetcher>,
                http_client: http_client.clone(),
                federation_poll_max_secs: Some(TEST_POLL_MAX_SECS),
            },
        ),
        access: AccessServerState::from_policy(
            access_policy,
            access_pending.clone(),
            keys.access_auth_jwt_minter(),
            AccessServerConfig {
                keys: keys.clone(),
                access_server_url: access_server_url.clone(),
                resource_url: resource_url.clone(),
                person_server_url: person_server_url.clone(),
                access_jwks_uri: access_jwks_uri.clone(),
                pending_base_url: access_server_url.clone(),
                pending_path: "/access/pending".into(),
                pending_ttl_secs: aauth::DEFAULT_PENDING_TTL_SECS,
                fetcher: Arc::clone(&fetcher) as Arc<dyn MetadataFetcher>,
            },
        ),
        resource: ResourceServerState {
            service: resource_service,
        },
        agent_jwks_uri: agent_jwks_uri.clone(),
    };

    let api = Router::new()
        .route("/api/data", get(api_data_handler))
        .route_layer(resource_auth_layer);

    let mut app = Router::new()
        .merge(api)
        .route("/.well-known/aauth-agent.json", get(agent_metadata_handler))
        .route("/agent/jwks", get(agent_jwks_handler));

    if config.with_auth_routes || config.federated {
        app = app
            .route(
                "/.well-known/aauth-person.json",
                get(person_metadata_handler),
            )
            .route("/auth/jwks", get(person_jwks_handler))
            .route("/aauth/token", post(token_exchange_handler))
            .route(
                "/pending/{id}",
                get(pending_poll_handler).post(pending_post_handler),
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
            )
            .route(
                "/as/access/pending/{id}",
                get(access_pending_poll_handler).post(access_pending_post_handler),
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
        metadata_fetcher: Arc::clone(&fetcher) as Arc<dyn MetadataFetcher>,
        person_pending,
        access_pending,
        resource_pending,
        opaque_store,
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
                agent: agent.identifier().to_string(),
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
        keys: state.person.config.keys.agent_root.jwk_set(),
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
