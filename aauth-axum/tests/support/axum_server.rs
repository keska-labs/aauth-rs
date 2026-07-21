use std::sync::Arc;

use aauth::AccessServerConfig;
use aauth::PendingOutcome;
use aauth::PersonServerConfig;
use aauth::TestKeys;
use aauth::VerifiedToken;
use aauth::access_server::keys::TestAccessAuthJwtMinter;
use aauth::metadata::{MetadataFetcher, StaticMetadataFetcher};
use aauth::person_server::keys::TestPersonAuthJwtMinter;
use aauth::protocol::{
    AgentOkResponse, AgentProviderMetadata, AuthOkResponse, JwksDocument, ResourceInteractionClaim,
    ResourceServerMetadata,
};
use aauth::resource::{
    ResourceAccessConfig, ResourceAccessMode, ResourceInteractionContext,
    ResourceInteractionProvider, ResourceTokenSigner,
};
use aauth_axum::{
    AccessServerState, PersonServerState, ResourceAuthLayer, ResourceServerState,
    VerifiedAAuthToken, access_router, person_router, resource_router,
};
use aauth_policy::{
    AlwaysGrantPersonPolicy, AlwaysGrantResourcePolicy, ClarificationThenGrantPersonPolicy,
    DeferInteractionAccessPolicy, DeferInteractionPersonPolicy, DeferInteractionResourcePolicy,
    InMemoryAccessPendingStore, InMemoryOpaqueAccessStore, InMemoryPersonPendingStore,
    InMemoryResourcePendingStore, OpaqueAccessStore, PendingStore, PolicyResourceAccessService,
};
use async_trait::async_trait;
use axum::Json;
use axum::Router;
use axum::extract::{FromRef, State};
use axum::routing::get;
use tokio::net::TcpListener;
use tokio::task::JoinHandle;

use super::harness_access_policy::HarnessAccessPolicy;
use super::harness_policy::HarnessPersonPolicy;
use super::harness_resource_policy::HarnessResourcePolicy;
use super::timeout::TEST_POLL_MAX_SECS;

#[derive(Clone)]
struct StaticResourceInteractionProvider {
    claim: ResourceInteractionClaim,
}

impl ResourceInteractionProvider for StaticResourceInteractionProvider {
    fn interaction_for(
        &self,
        _ctx: &ResourceInteractionContext,
    ) -> Option<ResourceInteractionClaim> {
        Some(self.claim.clone())
    }
}

/// Pending / grant behaviour for Person Server–asserted flows.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum PersonPending {
    #[default]
    Grant,
    Interaction,
    Clarification,
}

/// Pending / grant behaviour for Access Server (federated) flows.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum AccessPending {
    #[default]
    Grant,
    Interaction,
    Clarification,
}

/// Pending / grant behaviour for resource-managed consent.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum ResourcePending {
    Grant,
    #[default]
    Interaction,
}

/// Named access-mode scenario for the axum test harness (mirrors explorer modes).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TestScenario {
    IdentityBased,
    PersonManaged {
        pending: PersonPending,
        /// When true, the resource challenge includes a static interaction claim.
        resource_initiated_interaction: bool,
    },
    /// Local resource only; resource-token `aud` is a hosted Person Server URL.
    /// Used for `@aauth/fetch` hybrids against `person.hello.coop` (no local PS/AS).
    HostedPersonManaged {
        person_server_url: String,
    },
    ResourceManaged {
        pending: ResourcePending,
    },
    Federated {
        pending: AccessPending,
    },
}

impl TestScenario {
    pub fn identity_based() -> Self {
        Self::IdentityBased
    }

    pub fn person_managed() -> Self {
        Self::PersonManaged {
            pending: PersonPending::Grant,
            resource_initiated_interaction: false,
        }
    }

    pub fn person_managed_interaction() -> Self {
        Self::PersonManaged {
            pending: PersonPending::Interaction,
            resource_initiated_interaction: false,
        }
    }

    pub fn person_managed_clarification() -> Self {
        Self::PersonManaged {
            pending: PersonPending::Clarification,
            resource_initiated_interaction: false,
        }
    }

    pub fn person_managed_resource_interaction() -> Self {
        Self::PersonManaged {
            pending: PersonPending::Grant,
            resource_initiated_interaction: true,
        }
    }

    pub fn hosted_person_managed(person_server_url: impl Into<String>) -> Self {
        Self::HostedPersonManaged {
            person_server_url: person_server_url.into(),
        }
    }

    pub fn resource_managed() -> Self {
        Self::ResourceManaged {
            pending: ResourcePending::Interaction,
        }
    }

    pub fn federated() -> Self {
        Self::Federated {
            pending: AccessPending::Grant,
        }
    }

    pub fn federated_interaction() -> Self {
        Self::Federated {
            pending: AccessPending::Interaction,
        }
    }

    pub fn federated_clarification() -> Self {
        Self::Federated {
            pending: AccessPending::Clarification,
        }
    }
}

pub struct SpawnedServer {
    pub keys: TestKeys,
    pub agent_url: String,
    pub person_server_url: String,
    pub access_server_url: String,
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
        let id = self.person_pending.last_created.lock().unwrap().clone();
        if let Some(id) = id {
            let _ = self
                .person_pending
                .complete(
                    &id,
                    PendingOutcome::AuthToken(aauth::protocol::TokenResponseBody {
                        auth_token: auth_token.to_string(),
                        expires_in: 3600,
                    }),
                )
                .await;
        }
    }

    pub async fn resolve_resource_pending(&self, agent_id: &str) {
        let id = self.resource_pending.last_created.lock().unwrap().clone();
        if let Some(id) = id {
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
    aauth_policy::PolicyPersonTokenService<
        HarnessPersonPolicy,
        InMemoryPersonPendingStore,
        TestPersonAuthJwtMinter,
    >,
>;
type TestAccessState = AccessServerState<
    aauth_policy::PolicyAccessTokenService<
        HarnessAccessPolicy,
        InMemoryAccessPendingStore,
        TestAccessAuthJwtMinter,
    >,
>;
type TestResourceService = PolicyResourceAccessService<
    HarnessResourcePolicy,
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
    resource_jwks_uri: String,
    resource_url: String,
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

pub async fn spawn_test_server(scenario: TestScenario) -> SpawnedServer {
    let keys = aauth::TestKeys::generate();
    // Prefer a fixed bind (`AAUTH_E2E_BIND=127.0.0.1:PORT`) so a tunnel can front the
    // same port; otherwise pick an ephemeral port.
    let bind_addr = std::env::var("AAUTH_E2E_BIND")
        .ok()
        .filter(|s| !s.is_empty())
        .unwrap_or_else(|| "127.0.0.1:0".to_string());
    let listener = TcpListener::bind(&bind_addr)
        .await
        .unwrap_or_else(|e| panic!("bind {bind_addr}: {e}"));
    let addr = listener.local_addr().expect("local addr");
    // When a tunnel fronts this listener, advertise public URLs so hosted parties
    // can fetch JWKS and federate to the local Access Server.
    let base_url = std::env::var("AAUTH_E2E_PUBLIC_BASE")
        .ok()
        .filter(|s| !s.is_empty())
        .map(|s| s.trim_end_matches('/').to_string())
        .unwrap_or_else(|| format!("http://{addr}"));
    let agent_url = base_url.clone();
    let person_server_url = base_url.clone();
    let access_server_url = format!("{base_url}/as");
    let resource_url = base_url.clone();
    let agent_jwks_uri = format!("{base_url}/agent/jwks");
    let person_jwks_uri = format!("{base_url}/auth/jwks");
    let access_jwks_uri = format!("{access_server_url}/access/jwks");
    let resource_jwks_uri = format!("{base_url}/resource/jwks");

    let http_client = reqwest::Client::new();
    let http_fetcher = aauth_reqwest::CachedMetadataFetcher::new(http_client.clone());

    let fetcher: Arc<TriMetadataFetcher> = Arc::new(TriMetadataFetcher {
        agent: StaticMetadataFetcher::new(agent_jwks_uri.clone(), keys.agent_root.jwk_set()),
        person: StaticMetadataFetcher::new(person_jwks_uri.clone(), keys.person_server.jwk_set()),
        access: StaticMetadataFetcher::new(access_jwks_uri.clone(), keys.access_server.jwk_set()),
        resource: StaticMetadataFetcher::new(resource_jwks_uri.clone(), keys.resource.jwk_set()),
        agent_jwks_uri: agent_jwks_uri.clone(),
        person_jwks_uri: person_jwks_uri.clone(),
        access_jwks_uri: access_jwks_uri.clone(),
        resource_jwks_uri: resource_jwks_uri.clone(),
        local_base: base_url.clone(),
        http: http_fetcher,
    });

    let resource_token_signer: Arc<dyn ResourceTokenSigner> =
        Arc::new(keys.resource_token_signer());

    let opaque_store = InMemoryOpaqueAccessStore::new();
    let person_pending = InMemoryPersonPendingStore::new();
    let resource_pending = InMemoryResourcePendingStore::new();

    let access_pending = InMemoryAccessPendingStore::new();

    let person_policy = match &scenario {
        TestScenario::PersonManaged {
            pending: PersonPending::Clarification,
            ..
        } => HarnessPersonPolicy::Clarify(ClarificationThenGrantPersonPolicy {
            sub: "user-clarified".into(),
            question: "What is your purpose?".into(),
        }),
        TestScenario::PersonManaged {
            pending: PersonPending::Interaction,
            ..
        } => HarnessPersonPolicy::Defer(DeferInteractionPersonPolicy {
            inner: AlwaysGrantPersonPolicy::new("user-deferred"),
            interaction_url: format!("{person_server_url}/interact"),
        }),
        _ => HarnessPersonPolicy::Grant(AlwaysGrantPersonPolicy::new("user-123")),
    };

    let access_policy = match &scenario {
        TestScenario::Federated {
            pending: AccessPending::Clarification,
        } => HarnessAccessPolicy::Clarify(aauth_policy::ClarificationThenGrantAccessPolicy {
            sub: "user-federated".into(),
            question: "What is your purpose?".into(),
        }),
        TestScenario::Federated {
            pending: AccessPending::Interaction,
        } => HarnessAccessPolicy::Defer(DeferInteractionAccessPolicy {
            inner: aauth_policy::AlwaysGrantAccessPolicy::new("user-federated"),
            interaction_url: format!("{access_server_url}/interact"),
        }),
        _ => {
            HarnessAccessPolicy::Grant(aauth_policy::AlwaysGrantAccessPolicy::new("user-federated"))
        }
    };

    let resource_policy = match &scenario {
        TestScenario::ResourceManaged {
            pending: ResourcePending::Interaction,
        } => HarnessResourcePolicy::Defer(DeferInteractionResourcePolicy {
            interaction_url: format!("{resource_url}/interact"),
        }),
        _ => HarnessResourcePolicy::Grant(AlwaysGrantResourcePolicy),
    };

    let resource_service = PolicyResourceAccessService::new(
        resource_policy,
        resource_pending.clone(),
        opaque_store.clone(),
        ResourceAccessConfig {
            interaction_url: format!("{resource_url}/interact"),
            pending_base_url: resource_url.clone(),
            pending_path: "/resource/pending".into(),
            pending_ttl_secs: aauth::DEFAULT_PENDING_TTL_SECS,
        },
    );

    let (mode, with_person, with_access, with_resource, resource_initiated) = match &scenario {
        TestScenario::IdentityBased => (
            ResourceAccessMode::PsAsserted {
                require_auth_token: false,
                access_server_url: None,
                person_server_fallback: Some(person_server_url.clone()),
            },
            false,
            false,
            false,
            false,
        ),
        TestScenario::PersonManaged {
            resource_initiated_interaction,
            ..
        } => (
            ResourceAccessMode::PsAsserted {
                require_auth_token: true,
                access_server_url: None,
                person_server_fallback: Some(person_server_url.clone()),
            },
            true,
            false,
            false,
            *resource_initiated_interaction,
        ),
        TestScenario::HostedPersonManaged {
            person_server_url: hosted_ps,
        } => (
            ResourceAccessMode::PsAsserted {
                require_auth_token: true,
                access_server_url: None,
                person_server_fallback: Some(hosted_ps.clone()),
            },
            false,
            false,
            false,
            false,
        ),
        TestScenario::ResourceManaged { .. } => (
            ResourceAccessMode::ResourceManaged {
                service: resource_service.clone(),
            },
            false,
            false,
            true,
            false,
        ),
        TestScenario::Federated { .. } => (
            ResourceAccessMode::PsAsserted {
                require_auth_token: true,
                access_server_url: Some(access_server_url.clone()),
                person_server_fallback: Some(person_server_url.clone()),
            },
            true,
            true,
            false,
            false,
        ),
    };

    let resource_auth_layer = {
        let layer = ResourceAuthLayer::new(
            Arc::clone(&fetcher) as Arc<dyn MetadataFetcher>,
            resource_url.clone(),
            mode,
            resource_token_signer,
        );
        if resource_initiated {
            layer.with_interaction_provider(Arc::new(StaticResourceInteractionProvider {
                claim: ResourceInteractionClaim {
                    url: format!(
                        "{}/resource-interact",
                        resource_url.replace("http://", "https://")
                    ),
                    code: "R1S2-C3D4".into(),
                },
            }))
        } else {
            layer
        }
    };

    let test_state = TestServerState {
        person: PersonServerState::from_policy(
            person_policy,
            person_pending.clone(),
            keys.person_auth_jwt_minter(),
            PersonServerConfig {
                keys: keys.clone(),
                person_server_url: person_server_url.clone(),
                resource_url: resource_url.clone(),
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
        resource_jwks_uri: resource_jwks_uri.clone(),
        resource_url: resource_url.clone(),
    };

    let api = Router::new()
        .route("/api/data", get(api_data_handler))
        .route_layer(resource_auth_layer);

    let mut app = Router::new()
        .merge(api)
        .route("/.well-known/aauth-agent.json", get(agent_metadata_handler))
        .route("/agent/jwks", get(agent_jwks_handler))
        // Always publish resource JWKS/metadata so hosted PS/AS can verify resource tokens.
        .route(
            "/.well-known/aauth-resource.json",
            get(resource_metadata_handler),
        )
        .route("/resource/jwks", get(resource_jwks_handler));

    if with_person {
        app = app.merge(person_router::<TestServerState, _>());
    }

    if with_access {
        app = app.nest("/as", access_router::<TestServerState, _>());
    }

    if with_resource {
        app = app.merge(resource_router::<TestServerState, _>());
    }

    let app = app.with_state(test_state);

    let handle = tokio::spawn(async move {
        axum::serve(listener, app).await.expect("serve");
    });

    SpawnedServer {
        keys,
        agent_url,
        person_server_url,
        access_server_url,
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

async fn agent_metadata_handler(
    State(state): State<TestServerState>,
) -> Json<AgentProviderMetadata> {
    Json(AgentProviderMetadata::from_jwks_uri(state.agent_jwks_uri))
}

async fn agent_jwks_handler(State(state): State<TestServerState>) -> Json<JwksDocument> {
    Json(JwksDocument {
        keys: state.person.config.keys.agent_root.jwk_set(),
    })
}

async fn resource_metadata_handler(
    State(state): State<TestServerState>,
) -> Json<ResourceServerMetadata> {
    Json(ResourceServerMetadata {
        issuer: Some(state.resource_url.clone()),
        jwks_uri: Some(state.resource_jwks_uri.clone()),
        access_mode: None,
        name: Some("aauth-rs test resource".into()),
        description: None,
        logo_uri: None,
        logo_dark_uri: None,
        documentation_uri: None,
        tos_uri: None,
        policy_uri: None,
        authorization_endpoint: None,
        login_endpoint: None,
        scope_descriptions: None,
        signature_window: None,
        additional_signature_components: None,
        revocation_endpoint: None,
        r3_vocabularies: None,
    })
}

async fn resource_jwks_handler(State(state): State<TestServerState>) -> Json<JwksDocument> {
    Json(JwksDocument {
        keys: state.person.config.keys.resource.jwk_set(),
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
    /// Advertised local base URL; issuers under this host use in-memory TestKeys.
    local_base: String,
    /// HTTP fallback for remote agent / person / access issuers (hybrid e2e).
    http: aauth_reqwest::CachedMetadataFetcher,
}

fn issuer_is_local(local_base: &str, iss: &str) -> bool {
    let local = local_base.trim_end_matches('/');
    let iss = iss.trim_end_matches('/');
    iss == local || iss.starts_with(&format!("{local}/"))
}

#[async_trait]
impl MetadataFetcher for TriMetadataFetcher {
    async fn resolve_jwks_uri(&self, iss: &str, dwk: &str) -> aauth::Result<String> {
        if issuer_is_local(&self.local_base, iss) {
            return match dwk {
                "aauth-agent.json" => self.agent.resolve_jwks_uri(iss, dwk).await,
                "aauth-person.json" => self.person.resolve_jwks_uri(iss, dwk).await,
                "aauth-access.json" => self.access.resolve_jwks_uri(iss, dwk).await,
                "aauth-resource.json" => self.resource.resolve_jwks_uri(iss, dwk).await,
                _ => {
                    Err(aauth::MetadataError::UnknownJwksUri(format!("unknown dwk: {dwk}")).into())
                }
            };
        }
        self.http.resolve_jwks_uri(iss, dwk).await
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
            self.http.fetch_jwks(jwks_uri).await
        }
    }
}
