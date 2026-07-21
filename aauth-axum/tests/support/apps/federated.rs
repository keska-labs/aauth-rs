//! Federated (PS + AS) app definers.

use std::sync::Arc;

use aauth::AccessServerConfig;
use aauth::PersonServerConfig;
use aauth::TestKeys;
use aauth::metadata::MetadataFetcher;
use aauth::resource::ResourceAccessMode;
use aauth_axum::{
    AccessServerState, PersonServerState, ResourceAuthLayer, access_router, person_router,
};
use aauth_policy::{
    AccessTokenPolicy, AlwaysGrantAccessPolicy, AlwaysGrantPersonPolicy,
    ClarificationThenGrantAccessPolicy, DeferInteractionAccessPolicy, InMemoryAccessPendingStore,
    InMemoryPersonPendingStore, PersonTokenPolicy,
};
use axum::Router;
use axum::extract::FromRef;
use axum::routing::get;

use super::common::{ResourceDiscoveryState, api_data, resource_jwks, resource_metadata};
use crate::support::timeout::TEST_POLL_MAX_SECS;

/// Pending / grant behaviour for Access Server (federated) flows.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum AccessPolicyKind {
    #[default]
    Grant,
    Interaction,
    Clarification,
}

#[derive(Clone)]
enum AccessPolicy {
    Grant(AlwaysGrantAccessPolicy),
    Defer(DeferInteractionAccessPolicy<AlwaysGrantAccessPolicy>),
    Clarify(ClarificationThenGrantAccessPolicy),
}

#[async_trait::async_trait]
impl AccessTokenPolicy for AccessPolicy {
    async fn evaluate(
        &self,
        ctx: &aauth::AccessTokenContext,
    ) -> Result<aauth_policy::AccessTokenDecision, aauth_policy::PolicyError> {
        match self {
            Self::Grant(p) => p.evaluate(ctx).await,
            Self::Defer(p) => p.evaluate(ctx).await,
            Self::Clarify(p) => p.evaluate(ctx).await,
        }
    }

    async fn resume(
        &self,
        ctx: &aauth::AccessTokenContext,
        input: aauth::PendingInput,
    ) -> Result<aauth_policy::AccessTokenDecision, aauth_policy::PolicyError> {
        match self {
            Self::Grant(p) => p.resume(ctx, input).await,
            Self::Defer(p) => p.resume(ctx, input).await,
            Self::Clarify(p) => p.resume(ctx, input).await,
        }
    }
}

#[derive(Clone)]
struct FederatePersonPolicy;

#[async_trait::async_trait]
impl PersonTokenPolicy for FederatePersonPolicy {
    async fn evaluate(
        &self,
        ctx: &aauth::PersonTokenContext,
    ) -> Result<aauth_policy::PersonTokenDecision, aauth_policy::PolicyError> {
        AlwaysGrantPersonPolicy::new("user-federated")
            .evaluate(ctx)
            .await
    }

    async fn resume(
        &self,
        ctx: &aauth::PersonTokenContext,
        input: aauth::PendingInput,
    ) -> Result<aauth_policy::PersonTokenDecision, aauth_policy::PolicyError> {
        AlwaysGrantPersonPolicy::new("user-federated")
            .resume(ctx, input)
            .await
    }
}

type AccessState = AccessServerState<
    aauth_policy::PolicyAccessTokenService<
        AccessPolicy,
        InMemoryAccessPendingStore,
        aauth::access_server::keys::TestAccessAuthJwtMinter,
    >,
>;

type PersonState = PersonServerState<
    aauth_policy::PolicyPersonTokenService<
        FederatePersonPolicy,
        InMemoryPersonPendingStore,
        aauth::person_server::keys::TestPersonAuthJwtMinter,
    >,
>;

#[derive(Clone)]
struct AccessAppState {
    access: AccessState,
}

impl FromRef<AccessAppState> for AccessState {
    fn from_ref(input: &AccessAppState) -> AccessState {
        input.access.clone()
    }
}

#[derive(Clone)]
struct PersonAppState {
    person: PersonState,
}

impl FromRef<PersonAppState> for PersonState {
    fn from_ref(input: &PersonAppState) -> PersonState {
        input.person.clone()
    }
}

/// Parts returned by [`access_server_app`].
pub struct AccessServerParts {
    pub app: Router,
    pub pending: InMemoryAccessPendingStore,
}

/// Build an Access Server app (`access_router` + policy).
pub fn access_server_app(
    keys: &TestKeys,
    access_server_url: &str,
    person_server_url: &str,
    resource_url: &str,
    fetcher: Arc<dyn MetadataFetcher>,
    policy_kind: AccessPolicyKind,
) -> AccessServerParts {
    let pending = InMemoryAccessPendingStore::new();
    let policy = match policy_kind {
        AccessPolicyKind::Clarification => {
            AccessPolicy::Clarify(ClarificationThenGrantAccessPolicy {
                sub: "user-federated".into(),
                question: "What is your purpose?".into(),
            })
        }
        AccessPolicyKind::Interaction => AccessPolicy::Defer(DeferInteractionAccessPolicy {
            inner: AlwaysGrantAccessPolicy::new("user-federated"),
            interaction_url: format!("{}/interact", access_server_url.trim_end_matches('/')),
        }),
        AccessPolicyKind::Grant => {
            AccessPolicy::Grant(AlwaysGrantAccessPolicy::new("user-federated"))
        }
    };

    let access = AccessServerState::from_policy(
        policy,
        pending.clone(),
        keys.access_auth_jwt_minter(),
        AccessServerConfig {
            keys: keys.clone(),
            access_server_url: access_server_url.to_string(),
            resource_url: resource_url.to_string(),
            person_server_url: person_server_url.to_string(),
            access_jwks_uri: format!("{}/access/jwks", access_server_url.trim_end_matches('/')),
            pending_base_url: access_server_url.to_string(),
            pending_path: "/access/pending".into(),
            pending_ttl_secs: aauth::DEFAULT_PENDING_TTL_SECS,
            fetcher,
        },
    );

    let app = Router::new()
        .merge(access_router::<AccessAppState, _>())
        .with_state(AccessAppState { access });

    AccessServerParts { app, pending }
}

/// Parts returned by [`federated_person_server_app`].
pub struct FederatedPersonServerParts {
    pub app: Router,
    pub pending: InMemoryPersonPendingStore,
}

/// Build a Person Server that federates token exchange to an Access Server.
pub fn federated_person_server_app(
    keys: &TestKeys,
    person_server_url: &str,
    resource_url: &str,
    fetcher: Arc<dyn MetadataFetcher>,
) -> FederatedPersonServerParts {
    let pending = InMemoryPersonPendingStore::new();
    let person = PersonServerState::from_policy(
        FederatePersonPolicy,
        pending.clone(),
        keys.person_auth_jwt_minter(),
        PersonServerConfig {
            keys: keys.clone(),
            person_server_url: person_server_url.to_string(),
            resource_url: resource_url.to_string(),
            person_jwks_uri: format!("{}/auth/jwks", person_server_url.trim_end_matches('/')),
            interaction_url: format!("{}/interact", person_server_url.trim_end_matches('/')),
            pending_base_url: person_server_url.to_string(),
            pending_path: "/pending".into(),
            pending_ttl_secs: aauth::DEFAULT_PENDING_TTL_SECS,
            fetcher,
            http_client: reqwest::Client::new(),
            federation_poll_max_secs: Some(TEST_POLL_MAX_SECS),
        },
    );

    let app = Router::new()
        .merge(person_router::<PersonAppState, _>())
        .with_state(PersonAppState { person });

    FederatedPersonServerParts { app, pending }
}

/// Build a federated (PS-asserted with AS audience) resource server app.
pub fn federated_resource_app(
    keys: &TestKeys,
    resource_url: &str,
    person_server_url: &str,
    access_server_url: &str,
    fetcher: Arc<dyn MetadataFetcher>,
) -> Router {
    let mode = ResourceAccessMode::<aauth::NoResourceAccessService>::PsAsserted {
        require_auth_token: true,
        access_server_url: Some(access_server_url.to_string()),
        person_server_fallback: Some(person_server_url.to_string()),
    };

    let layer = ResourceAuthLayer::new(
        fetcher,
        resource_url.to_string(),
        mode,
        Arc::new(keys.resource_token_signer()),
    );

    let state = ResourceDiscoveryState::from_keys(keys, resource_url);

    Router::new()
        .route("/api/data", get(api_data))
        .route_layer(layer)
        .route("/.well-known/aauth-resource.json", get(resource_metadata))
        .route("/jwks", get(resource_jwks))
        .with_state(state)
}
