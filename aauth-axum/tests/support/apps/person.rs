//! Person Server and person-managed resource app definers.

use std::sync::Arc;

use crate::support::metadata::MultiPartyMetadataFetcher;
use aauth::PersonServerConfig;
use aauth::TestKeys;
use aauth::protocol::ResourceInteractionClaim;
use aauth::resource::{
    ResourceAccessMode, ResourceInteractionContext, ResourceInteractionProvider,
};
use aauth_axum::{PersonServerState, ResourceAuthLayer, person_router};
use aauth_policy::{
    AlwaysGrantPersonPolicy, ClarificationThenGrantPersonPolicy, DeferInteractionPersonPolicy,
    InMemoryPersonPendingStore, PersonTokenPolicy,
};
use axum::Router;
use axum::extract::FromRef;
use axum::routing::get;

use super::common::{ResourceDiscoveryState, api_data, resource_jwks, resource_metadata};
use crate::support::timeout::TEST_POLL_MAX_SECS;

/// Pending / grant behaviour for Person Server–asserted flows.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum PersonPolicyKind {
    #[default]
    Grant,
    Interaction,
    Clarification,
}

#[derive(Clone)]
enum PersonPolicy {
    Grant(AlwaysGrantPersonPolicy),
    Defer(DeferInteractionPersonPolicy<AlwaysGrantPersonPolicy>),
    Clarify(ClarificationThenGrantPersonPolicy),
}

impl PersonTokenPolicy for PersonPolicy {
    async fn evaluate(
        &self,
        ctx: &aauth::PersonTokenContext,
    ) -> Result<aauth_policy::PersonTokenDecision, aauth_policy::PolicyError> {
        match self {
            Self::Grant(p) => p.evaluate(ctx).await,
            Self::Defer(p) => p.evaluate(ctx).await,
            Self::Clarify(p) => p.evaluate(ctx).await,
        }
    }

    async fn resume(
        &self,
        ctx: &aauth::PersonTokenContext,
        input: aauth::PendingInput,
    ) -> Result<aauth_policy::PersonTokenDecision, aauth_policy::PolicyError> {
        match self {
            Self::Grant(p) => p.resume(ctx, input).await,
            Self::Defer(p) => p.resume(ctx, input).await,
            Self::Clarify(p) => p.resume(ctx, input).await,
        }
    }
}

type PersonState = PersonServerState<
    aauth_policy::PolicyPersonTokenService<
        PersonPolicy,
        InMemoryPersonPendingStore,
        aauth::person_server::keys::TestPersonAuthJwtMinter,
        Arc<MultiPartyMetadataFetcher>,
    >,
    Arc<MultiPartyMetadataFetcher>,
>;

#[derive(Clone)]
struct PersonAppState {
    person: PersonState,
}

impl FromRef<PersonAppState> for PersonState {
    fn from_ref(input: &PersonAppState) -> PersonState {
        input.person.clone()
    }
}

/// Parts returned by [`person_server_app`].
pub struct PersonServerParts {
    pub app: Router,
    pub pending: InMemoryPersonPendingStore,
}

/// Build a Person Server app (`person_router` + policy).
pub fn person_server_app(
    keys: &TestKeys,
    person_server_url: &str,
    resource_url: &str,
    fetcher: Arc<MultiPartyMetadataFetcher>,
    policy_kind: PersonPolicyKind,
) -> PersonServerParts {
    let pending = InMemoryPersonPendingStore::new();
    let policy = match policy_kind {
        PersonPolicyKind::Clarification => {
            PersonPolicy::Clarify(ClarificationThenGrantPersonPolicy {
                sub: "user-clarified".into(),
                question: "What is your purpose?".into(),
            })
        }
        PersonPolicyKind::Interaction => PersonPolicy::Defer(DeferInteractionPersonPolicy {
            inner: AlwaysGrantPersonPolicy::new("user-deferred"),
            interaction_url: format!("{}/interact", person_server_url.trim_end_matches('/')),
        }),
        PersonPolicyKind::Grant => PersonPolicy::Grant(AlwaysGrantPersonPolicy::new("user-123")),
    };

    let person = PersonServerState::from_policy(
        policy,
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

    let state = PersonAppState { person };
    let app = Router::new()
        .merge(person_router::<PersonAppState, _, _>())
        .with_state(state);

    PersonServerParts { app, pending }
}

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

/// Build a person-managed (PS-asserted) resource server app.
pub fn person_managed_resource_app(
    keys: &TestKeys,
    resource_url: &str,
    person_server_url: &str,
    fetcher: Arc<MultiPartyMetadataFetcher>,
    resource_initiated_interaction: bool,
) -> Router {
    let mode = ResourceAccessMode::<aauth::NoResourceAccessService>::PsAsserted {
        require_auth_token: true,
        access_server_url: None,
        person_server_fallback: Some(person_server_url.to_string()),
    };

    let state = ResourceDiscoveryState::from_keys(keys, resource_url);
    let signer = Arc::new(keys.resource_token_signer());

    if resource_initiated_interaction {
        let layer = ResourceAuthLayer::new(fetcher, resource_url.to_string(), mode, signer)
            .with_interaction_provider(Arc::new(StaticResourceInteractionProvider {
                claim: ResourceInteractionClaim {
                    url: format!(
                        "{}/resource-interact",
                        resource_url.replace("http://", "https://")
                    ),
                    code: "R1S2-C3D4".into(),
                },
            }));
        Router::new()
            .route("/api/data", get(api_data))
            .route_layer(layer)
            .route("/.well-known/aauth-resource.json", get(resource_metadata))
            .route("/jwks", get(resource_jwks))
            .with_state(state)
    } else {
        let layer = ResourceAuthLayer::new(fetcher, resource_url.to_string(), mode, signer);
        Router::new()
            .route("/api/data", get(api_data))
            .route_layer(layer)
            .route("/.well-known/aauth-resource.json", get(resource_metadata))
            .route("/jwks", get(resource_jwks))
            .with_state(state)
    }
}

/// Local resource only; resource-token `aud` is a hosted Person Server URL.
pub fn hosted_person_managed_resource_app(
    keys: &TestKeys,
    resource_url: &str,
    hosted_person_server_url: &str,
    fetcher: Arc<MultiPartyMetadataFetcher>,
) -> Router {
    person_managed_resource_app(keys, resource_url, hosted_person_server_url, fetcher, false)
}
