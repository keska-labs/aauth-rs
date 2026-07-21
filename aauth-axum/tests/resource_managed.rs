//! Resource-managed (two-party opaque access) mode.

mod support;

use std::sync::Arc;
use std::time::Duration;

use aauth::TestKeys;
use aauth::protocol::AgentOkResponse;
use aauth_policy::{OpaqueAccessStore, PendingStore};
use rstest::rstest;

use support::AGENT_ID;
use support::agent_issuer::agent_issuer_app;
use support::apps::{ResourcePolicyKind, resource_managed_app};
use support::client::AgentClientBuilder;
use support::listen::{bind_ephemeral, serve};
use support::metadata::MultiPartyMetadataFetcher;

#[rstest]
#[timeout(Duration::from_secs(1))]
#[tokio::test]
async fn resource_managed_interaction_over_http() {
    let keys = TestKeys::generate();
    let (agent_listener, agent_url) = bind_ephemeral().await;
    let agent = serve(
        agent_listener,
        agent_issuer_app(&keys, &agent_url),
        agent_url,
    );

    let (resource_listener, resource_url) = bind_ephemeral().await;
    let fetcher = MultiPartyMetadataFetcher::builder(&keys, &agent.url, &resource_url).build();
    let parts = resource_managed_app(
        &keys,
        &resource_url,
        Arc::clone(&fetcher),
        ResourcePolicyKind::Interaction,
    );
    let resource_pending_cb = parts.pending.clone();
    let opaque_store_cb = parts.opaque_store.clone();
    let resource = serve(resource_listener, parts.app, resource_url);

    let on_interaction = Arc::new(move |_url: String, _code: String| {
        let pending = resource_pending_cb.clone();
        let opaque = opaque_store_cb.issue(AGENT_ID);
        let pending_id = resource_pending_cb.last_created.lock().unwrap().clone();
        tokio::spawn(async move {
            if let Some(id) = pending_id {
                let _ = pending
                    .complete(&id, aauth::PendingOutcome::OpaqueAccess(opaque))
                    .await;
            }
        });
    });

    let client = AgentClientBuilder::new(&keys, &agent.url, fetcher)
        .on_interaction(on_interaction)
        .build();
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
async fn resource_managed_always_grant_over_http() {
    let keys = TestKeys::generate();
    let (agent_listener, agent_url) = bind_ephemeral().await;
    let agent = serve(
        agent_listener,
        agent_issuer_app(&keys, &agent_url),
        agent_url,
    );

    let (resource_listener, resource_url) = bind_ephemeral().await;
    let fetcher = MultiPartyMetadataFetcher::builder(&keys, &agent.url, &resource_url).build();
    let parts = resource_managed_app(
        &keys,
        &resource_url,
        Arc::clone(&fetcher),
        ResourcePolicyKind::Grant,
    );
    let resource = serve(resource_listener, parts.app, resource_url);

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
