//! Federated access (four-party): Person Server delegates to an Access Server.
//!
//! Matches the [Federated](https://explorer.aauth.dev/) flow. The resource token audience
//! is the Access Server; the Person Server federates the token exchange to the AS.

mod support;

use std::sync::Arc;

use aauth::AccessServerConfig;
use aauth::ParsedToken;
use aauth::PersonServerConfig;
use aauth::TestKeys;
use aauth::protocol::{AuthOkResponse, JwksDocument, ResourceServerMetadata};
use aauth::resource::ResourceAccessMode;
use aauth_axum::{
    AccessServerState, PersonServerState, ResourceAuthLayer, VerifiedAAuthToken, access_router,
    person_router,
};
use aauth_policy::{
    AlwaysGrantAccessPolicy, AlwaysGrantPersonPolicy, InMemoryAccessPendingStore,
    InMemoryPersonPendingStore,
};
use axum::Json;
use axum::Router;
use axum::extract::{FromRef, State};
use axum::routing::get;

use support::timeout::TEST_POLL_MAX_SECS;
use support::{
    AgentClientBuilder, MultiPartyMetadataFetcher, agent_issuer_app, bind_ephemeral, serve,
};

#[derive(Clone)]
struct ResourceState {
    resource_url: String,
    resource_jwks: JwksDocument,
}

type PersonState = PersonServerState<
    aauth_policy::PolicyPersonTokenService<
        AlwaysGrantPersonPolicy,
        InMemoryPersonPendingStore,
        aauth::person_server::keys::TestPersonAuthJwtMinter,
        Arc<MultiPartyMetadataFetcher>,
        aauth_reqwest::ReqwestAccessServerClient,
    >,
    Arc<MultiPartyMetadataFetcher>,
    aauth_reqwest::ReqwestAccessServerClient,
>;

type AccessState = AccessServerState<
    aauth_policy::PolicyAccessTokenService<
        AlwaysGrantAccessPolicy,
        InMemoryAccessPendingStore,
        aauth::access_server::keys::TestAccessAuthJwtMinter,
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

#[derive(Clone)]
struct AccessAppState {
    access: AccessState,
}

impl FromRef<AccessAppState> for AccessState {
    fn from_ref(input: &AccessAppState) -> AccessState {
        input.access.clone()
    }
}

fn person_server_app(
    keys: &TestKeys,
    person_server_url: &str,
    resource_url: &str,
    fetcher: Arc<MultiPartyMetadataFetcher>,
) -> Router {
    let person = PersonServerState::from_policy(
        AlwaysGrantPersonPolicy::new("user-federated"),
        InMemoryPersonPendingStore::new(),
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
            access_server: aauth_reqwest::ReqwestAccessServerClient::new(
                reqwest::Client::new(),
                aauth::PersonServerOutboundSigner::new(keys.clone(), person_server_url.to_string()),
            ),
            federation_poll_max_secs: Some(TEST_POLL_MAX_SECS),
        },
    );

    Router::new()
        .merge(person_router::<PersonAppState, _, _, _>())
        .with_state(PersonAppState { person })
}

fn access_server_app(
    keys: &TestKeys,
    access_server_url: &str,
    person_server_url: &str,
    resource_url: &str,
    fetcher: Arc<MultiPartyMetadataFetcher>,
) -> Router {
    let access = AccessServerState::from_policy(
        AlwaysGrantAccessPolicy::new("user-federated"),
        InMemoryAccessPendingStore::new(),
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

    Router::new()
        .merge(access_router::<AccessAppState, _, _>())
        .with_state(AccessAppState { access })
}

fn federated_resource_app(
    keys: &TestKeys,
    resource_url: &str,
    person_server_url: &str,
    access_server_url: &str,
    fetcher: Arc<MultiPartyMetadataFetcher>,
) -> Router {
    let layer = ResourceAuthLayer::new(
        fetcher,
        resource_url.to_string(),
        ResourceAccessMode::<aauth::NoResourceAccessService>::PsAsserted {
            require_auth_token: true,
            access_server_url: Some(access_server_url.to_string()),
            person_server_fallback: Some(person_server_url.to_string()),
        },
        Arc::new(keys.resource_token_signer()),
    );

    let state = ResourceState {
        resource_url: resource_url.to_string(),
        resource_jwks: JwksDocument {
            keys: keys.resource.jwk_set(),
        },
    };

    Router::new()
        .route("/api/data", get(api_data))
        .route_layer(layer)
        .route("/.well-known/aauth-resource.json", get(resource_metadata))
        .route("/jwks", get(resource_jwks))
        .with_state(state)
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let keys = TestKeys::generate();

    let (agent_listener, agent_url) = bind_ephemeral().await;
    let agent = serve(
        agent_listener,
        agent_issuer_app(&keys, &agent_url),
        agent_url,
    );

    let (person_listener, person_url) = bind_ephemeral().await;
    let (access_listener, access_url) = bind_ephemeral().await;
    let (resource_listener, resource_url) = bind_ephemeral().await;

    let fetcher = MultiPartyMetadataFetcher::builder(&keys, &agent.url, &resource_url)
        .person_server(&person_url)
        .access_server(&access_url)
        .build();

    let person = serve(
        person_listener,
        person_server_app(&keys, &person_url, &resource_url, Arc::clone(&fetcher)),
        person_url,
    );
    let access = serve(
        access_listener,
        access_server_app(
            &keys,
            &access_url,
            &person.url,
            &resource_url,
            Arc::clone(&fetcher),
        ),
        access_url,
    );
    let resource = serve(
        resource_listener,
        federated_resource_app(
            &keys,
            &resource_url,
            &person.url,
            &access.url,
            Arc::clone(&fetcher),
        ),
        resource_url,
    );

    let client = AgentClientBuilder::new(&keys, &agent.url, fetcher)
        .with_person_server(&person.url)
        .build();
    let response = client
        .get(format!("{}/api/data", resource.url))
        .send()
        .await?;

    println!("status: {}", response.status());
    let body: AuthOkResponse = response.json().await?;
    println!("user: {:?}", body.user);

    Ok(())
}

async fn api_data(token: VerifiedAAuthToken) -> Json<serde_json::Value> {
    match token.0 {
        ParsedToken::Auth(auth) => Json(serde_json::json!({
            "status": "ok",
            "user": auth.sub,
        })),
        ParsedToken::Agent(agent) => Json(serde_json::json!({
            "status": "ok",
            "agent": agent.identifier().to_string(),
        })),
        ParsedToken::Resource(_) => Json(serde_json::json!({
            "status": "error",
            "error": "unexpected_resource_token",
        })),
    }
}

async fn resource_metadata(State(state): State<ResourceState>) -> Json<ResourceServerMetadata> {
    Json(ResourceServerMetadata {
        issuer: Some(state.resource_url.clone()),
        jwks_uri: Some(format!("{}/jwks", state.resource_url.trim_end_matches('/'))),
        access_mode: None,
        name: Some("aauth-rs example resource".into()),
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

async fn resource_jwks(State(state): State<ResourceState>) -> Json<JwksDocument> {
    Json(state.resource_jwks.clone())
}
