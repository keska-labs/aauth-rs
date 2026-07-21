//! Identity-based access mode (agent JWT alone).

mod support;

use std::sync::Arc;
use std::time::Duration;

use aauth::TestKeys;
use aauth::protocol::AgentOkResponse;
use rstest::rstest;

use support::AGENT_ID;
use support::agent_issuer::agent_issuer_app;
use support::apps::identity_resource_app;
use support::client::AgentClientBuilder;
use support::listen::{bind_ephemeral, serve};
use support::metadata::MultiPartyMetadataFetcher;

async fn spawn_identity() -> (
    TestKeys,
    support::listen::Serving,
    support::listen::Serving,
    Arc<crate::support::metadata::MultiPartyMetadataFetcher>,
) {
    let keys = TestKeys::generate();
    let (agent_listener, agent_url) = bind_ephemeral().await;
    let agent = serve(
        agent_listener,
        agent_issuer_app(&keys, &agent_url),
        agent_url,
    );

    let (resource_listener, resource_url) = bind_ephemeral().await;
    let fetcher = MultiPartyMetadataFetcher::builder(&keys, &agent.url, &resource_url).build();
    let resource = serve(
        resource_listener,
        identity_resource_app(&keys, &resource_url, Arc::clone(&fetcher)),
        resource_url,
    );
    (keys, agent, resource, fetcher)
}

#[rstest]
#[timeout(Duration::from_secs(1))]
#[tokio::test]
async fn identity_based_over_http() {
    let (keys, agent, resource, fetcher) = spawn_identity().await;

    let client = AgentClientBuilder::new(&keys, &agent.url, fetcher).build();
    let response = client
        .get(format!("{}/api/data", resource.url))
        .send()
        .await
        .expect("request");

    assert!(response.status().is_success());
    let body: AgentOkResponse = response.json().await.expect("json");
    assert_eq!(body.status, "ok");
    assert_eq!(body.agent, AGENT_ID);
}

#[rstest]
#[timeout(Duration::from_secs(1))]
#[tokio::test]
async fn unsigned_request_rejected_over_http() {
    let (_keys, _agent, resource, _fetcher) = spawn_identity().await;

    let response = reqwest::Client::new()
        .get(format!("{}/api/data", resource.url))
        .send()
        .await
        .expect("request");

    assert_eq!(response.status(), reqwest::StatusCode::UNAUTHORIZED);
}

#[rstest]
#[timeout(Duration::from_secs(1))]
#[tokio::test]
async fn invalid_signature_rejected_over_http() {
    let (keys, agent, resource, fetcher) = spawn_identity().await;

    let wrong_keys = TestKeys::generate();
    let agent_jwt = wrong_keys.mint_agent_jwt(&agent.url, AGENT_ID, None);
    let provider = wrong_keys.key_provider(agent_jwt);

    let client = AgentClientBuilder::new(&keys, &agent.url, fetcher)
        .provider(provider)
        .build();
    let response = client
        .get(format!("{}/api/data", resource.url))
        .send()
        .await
        .expect("request");

    assert_eq!(response.status(), reqwest::StatusCode::UNAUTHORIZED);
}
