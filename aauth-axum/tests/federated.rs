//! Federated (four-party) access mode.

mod support;

use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use aauth::protocol::AuthOkResponse;
use aauth_reqwest::{ClarificationCallback, InteractionCallback};
use http::header::CONTENT_TYPE;
use rstest::rstest;

use support::axum_server::{TestScenario, spawn_test_server};

#[rstest]
#[timeout(Duration::from_secs(1))]
#[tokio::test]
async fn federated_over_http() {
    let spawned = spawn_test_server(TestScenario::federated()).await;

    let client = spawned.agent().with_spawned_person_server().build();
    let response = client
        .get(format!("{}/api/data", spawned.resource_url))
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
    let spawned = spawn_test_server(TestScenario::federated_clarification()).await;

    let received_clarification = Arc::new(Mutex::new(None));
    let received_clarification_cb = Arc::clone(&received_clarification);

    let on_clarification: ClarificationCallback = Arc::new(move |prompt| {
        let received = Arc::clone(&received_clarification_cb);
        Box::pin(async move {
            *received.lock().unwrap() = Some(prompt);
            "To help users".into()
        })
    });

    let client = spawned
        .agent()
        .with_spawned_person_server()
        .on_clarification(on_clarification)
        .build();

    let response = client
        .get(format!("{}/api/data", spawned.resource_url))
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
    let spawned = spawn_test_server(TestScenario::federated_interaction()).await;

    let received = Arc::new(Mutex::new(None));
    let received_cb = Arc::clone(&received);
    let person_url = spawned.person_server_url.clone();
    let person_pending_cb = spawned.person_pending.clone();
    let expected_interaction_url = format!("{}/as/interact", spawned.person_server_url);
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

    let client = spawned
        .agent()
        .with_spawned_person_server()
        .on_interaction(on_interaction)
        .build();

    let response = client
        .get(format!("{}/api/data", spawned.resource_url))
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
