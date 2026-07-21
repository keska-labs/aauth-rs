//! Federated (four-party) access mode.

mod support;

use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use aauth::TestKeys;
use aauth::protocol::AuthOkResponse;
use aauth_reqwest::{ClarificationCallback, InteractionCallback};
use http::header::CONTENT_TYPE;
use rstest::rstest;

use support::agent_issuer::agent_issuer_app;
use support::apps::{
    AccessPolicyKind, access_server_app, federated_person_server_app, federated_resource_app,
};
use support::client::AgentClientBuilder;
use support::listen::{Serving, bind_ephemeral, serve};
use support::metadata::MultiPartyMetadataFetcher;

struct FederatedParties {
    keys: TestKeys,
    agent: Serving,
    person: Serving,
    access: Serving,
    resource: Serving,
    person_pending: aauth_policy::InMemoryPersonPendingStore,
    fetcher: Arc<dyn aauth::metadata::MetadataFetcher>,
}

async fn spawn_federated(access_policy: AccessPolicyKind) -> FederatedParties {
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

    let person_parts =
        federated_person_server_app(&keys, &person_url, &resource_url, Arc::clone(&fetcher));
    let person_pending = person_parts.pending;
    let access_parts = access_server_app(
        &keys,
        &access_url,
        &person_url,
        &resource_url,
        Arc::clone(&fetcher),
        access_policy,
    );
    let person = serve(person_listener, person_parts.app, person_url);
    let access = serve(access_listener, access_parts.app, access_url);
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

    FederatedParties {
        keys,
        agent,
        person,
        access,
        resource,
        person_pending,
        fetcher,
    }
}

#[rstest]
#[timeout(Duration::from_secs(1))]
#[tokio::test]
async fn federated_over_http() {
    let parties = spawn_federated(AccessPolicyKind::Grant).await;

    let client = AgentClientBuilder::new(&parties.keys, &parties.agent.url, parties.fetcher)
        .with_person_server(&parties.person.url)
        .build();
    let response = client
        .get(format!("{}/api/data", parties.resource.url))
        .send()
        .await
        .expect("request");

    assert!(response.status().is_success());
    let body: AuthOkResponse = response.json().await.expect("json");
    assert_eq!(body.status, "ok");
    assert_eq!(body.user.as_deref(), Some("user-federated"));
}

#[rstest]
#[timeout(Duration::from_secs(1))]
#[tokio::test]
async fn federated_as_clarification_deferred_over_http() {
    let parties = spawn_federated(AccessPolicyKind::Clarification).await;

    let received_clarification = Arc::new(Mutex::new(None));
    let received_clarification_cb = Arc::clone(&received_clarification);

    let on_clarification: ClarificationCallback = Arc::new(move |prompt| {
        let received = Arc::clone(&received_clarification_cb);
        Box::pin(async move {
            *received.lock().unwrap() = Some(prompt);
            "To help users".into()
        })
    });

    let client = AgentClientBuilder::new(&parties.keys, &parties.agent.url, parties.fetcher)
        .with_person_server(&parties.person.url)
        .on_clarification(on_clarification)
        .build();

    let response = client
        .get(format!("{}/api/data", parties.resource.url))
        .send()
        .await
        .expect("request");

    assert!(response.status().is_success());
    let body: AuthOkResponse = response.json().await.expect("json");
    assert_eq!(body.user.as_deref(), Some("user-federated"));
    assert_eq!(
        received_clarification.lock().unwrap().as_deref(),
        Some("What is your purpose?")
    );
}

#[rstest]
#[timeout(Duration::from_secs(1))]
#[tokio::test]
async fn federated_as_interaction_deferred_over_http() {
    let parties = spawn_federated(AccessPolicyKind::Interaction).await;

    let received = Arc::new(Mutex::new(None));
    let received_cb = Arc::clone(&received);
    let person_url = parties.person.url.clone();
    let person_pending_cb = parties.person_pending.clone();
    let expected_interaction_url = format!("{}/interact", parties.access.url);
    let posted = Arc::new(AtomicBool::new(false));

    let on_interaction: InteractionCallback = Arc::new(move |url, code| {
        *received_cb.lock().unwrap() = Some((url.clone(), code.clone()));
        if posted.swap(true, Ordering::SeqCst) {
            return;
        }
        let person_url = person_url.clone();
        let pending = person_pending_cb.clone();
        tokio::spawn(async move {
            for _ in 0..100 {
                if pending.last_created.lock().unwrap().is_some() {
                    break;
                }
                tokio::time::sleep(std::time::Duration::from_millis(5)).await;
            }
            let pending_id = pending.last_created.lock().unwrap().clone();
            let Some(id) = pending_id else {
                panic!("person pending id not available after interaction callback");
            };
            let response = reqwest::Client::new()
                .post(format!("{person_url}/pending/{id}"))
                .header(CONTENT_TYPE, "application/json")
                .body("{}")
                .send()
                .await
                .expect("post pending");
            assert!(
                response.status().is_success(),
                "PS pending POST failed: {}",
                response.status()
            );
        });
    });

    let client = AgentClientBuilder::new(&parties.keys, &parties.agent.url, parties.fetcher)
        .with_person_server(&parties.person.url)
        .on_interaction(on_interaction)
        .build();

    let response = client
        .get(format!("{}/api/data", parties.resource.url))
        .send()
        .await
        .expect("request");

    assert!(response.status().is_success());
    let body: AuthOkResponse = response.json().await.expect("json");
    assert_eq!(body.user.as_deref(), Some("user-federated"));
    let interaction = received.lock().unwrap().clone();
    assert!(interaction.is_some());
    let (url, code) = interaction.unwrap();
    assert_eq!(url, expected_interaction_url);
    assert!(!code.is_empty());
}
