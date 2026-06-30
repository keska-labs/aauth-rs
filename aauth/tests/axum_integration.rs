//! Client + server integration tests over real HTTP (axum + reqwest).

mod support;

use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use aauth::agent::reqwest::{ClarificationCallback, InteractionCallback};
use aauth::types::AuthOkResponse;
use aauth::{PendingStore, create_key_provider, create_test_keys, mint_agent_jwt, mint_auth_jwt};
use rstest::rstest;

use support::axum_server::{ServerConfig, spawn_test_server};
use support::client::{AGENT_ID, build_client};

#[rstest]
#[timeout(Duration::from_secs(1))]
#[tokio::test]
async fn person_server_managed_ps_from_agent_claim_over_http() {
    let spawned = spawn_test_server(ServerConfig {
        require_auth_token: true,
        with_auth_routes: true,
        ..Default::default()
    })
    .await;

    let client = build_client(
        &spawned,
        Some(spawned.person_server_url.clone()),
        Some(&spawned.person_server_url),
        None,
        None,
        None,
    );
    let response = client
        .get(format!("{}/api/data", spawned.resource_url))
        .send()
        .await
        .expect("request");

    assert!(response.status().is_success());
    let body: AuthOkResponse = response.json().await.expect("json");
    assert_eq!(body.user.as_deref(), Some("user-123"));
}

#[rstest]
#[timeout(Duration::from_secs(1))]
#[tokio::test]
async fn unsigned_request_rejected_over_http() {
    let spawned = spawn_test_server(ServerConfig {
        require_auth_token: false,
        with_auth_routes: false,
        ..Default::default()
    })
    .await;

    let response = reqwest::Client::new()
        .get(format!("{}/api/data", spawned.resource_url))
        .send()
        .await
        .expect("request");

    assert_eq!(response.status(), reqwest::StatusCode::UNAUTHORIZED);
}

#[rstest]
#[timeout(Duration::from_secs(1))]
#[tokio::test]
async fn deferred_interaction_over_http() {
    let spawned = spawn_test_server(ServerConfig {
        require_auth_token: true,
        with_auth_routes: true,
        deferred_mode: true,
        clarification_on_poll: false,
        ..Default::default()
    })
    .await;

    let interaction_url = format!("{}/interact", spawned.person_server_url);
    let received = Arc::new(Mutex::new(None));
    let received_cb = Arc::clone(&received);
    let person_pending_cb = spawned.person_pending.clone();
    let keys_cb = spawned.keys.clone();
    let resource_url = spawned.resource_url.clone();
    let person_server_url = spawned.person_server_url.clone();

    let on_interaction: InteractionCallback = Arc::new(move |url, code| {
        *received_cb.lock().unwrap() = Some((url.clone(), code.clone()));
        let auth_jwt = mint_auth_jwt(
            &keys_cb,
            &person_server_url,
            &resource_url,
            AGENT_ID,
            Some("user-deferred"),
            None,
        );
        let pending = person_pending_cb.clone();
        let pending_id = person_pending_cb.last_created.lock().unwrap().clone();
        tokio::spawn(async move {
            if let Some(id) = pending_id {
                pending
                    .complete(
                        &id,
                        aauth::PendingOutcome::AuthToken(aauth::types::TokenResponseBody {
                            auth_token: auth_jwt,
                            expires_in: 3600,
                        }),
                    )
                    .await
                    .expect("complete");
            }
        });
    });

    let client = build_client(
        &spawned,
        Some(spawned.person_server_url.clone()),
        Some(&spawned.person_server_url),
        Some(on_interaction),
        None,
        None,
    );

    let response = client
        .get(format!("{}/api/data", spawned.resource_url))
        .send()
        .await
        .expect("request");

    assert!(response.status().is_success());
    let body: AuthOkResponse = response.json().await.expect("json");
    assert_eq!(body.user.as_deref(), Some("user-deferred"));

    let interaction = received.lock().unwrap().clone();
    assert!(interaction.is_some());
    let (url, code) = interaction.unwrap();
    assert_eq!(url, interaction_url);
    assert!(!code.is_empty());
}

#[rstest]
#[timeout(Duration::from_secs(1))]
#[tokio::test]
async fn clarification_deferred_over_http() {
    let spawned = spawn_test_server(ServerConfig {
        require_auth_token: true,
        with_auth_routes: true,
        deferred_mode: true,
        clarification_on_poll: true,
        ..Default::default()
    })
    .await;

    let received_clarification = Arc::new(Mutex::new(None));
    let received_clarification_cb = Arc::clone(&received_clarification);

    let on_clarification: ClarificationCallback = Arc::new(move |prompt| {
        let received = Arc::clone(&received_clarification_cb);
        Box::pin(async move {
            *received.lock().unwrap() = Some(prompt);
            "To help users".into()
        })
    });

    let client = build_client(
        &spawned,
        Some(spawned.person_server_url.clone()),
        Some(&spawned.person_server_url),
        None,
        Some(on_clarification),
        None,
    );

    let response = client
        .get(format!("{}/api/data", spawned.resource_url))
        .send()
        .await
        .expect("request");

    assert!(response.status().is_success());
    let body: AuthOkResponse = response.json().await.expect("json");
    assert_eq!(body.user.as_deref(), Some("user-clarified"));
    assert_eq!(
        received_clarification.lock().unwrap().as_deref(),
        Some("What is your purpose?")
    );
}

#[rstest]
#[timeout(Duration::from_secs(1))]
#[tokio::test]
async fn federated_as_clarification_deferred_over_http() {
    let spawned = spawn_test_server(ServerConfig {
        require_auth_token: true,
        with_auth_routes: true,
        federated: true,
        as_clarification: true,
        ..Default::default()
    })
    .await;

    let received_clarification = Arc::new(Mutex::new(None));
    let received_clarification_cb = Arc::clone(&received_clarification);

    let on_clarification: ClarificationCallback = Arc::new(move |prompt| {
        let received = Arc::clone(&received_clarification_cb);
        Box::pin(async move {
            *received.lock().unwrap() = Some(prompt);
            "To help users".into()
        })
    });

    let client = build_client(
        &spawned,
        Some(spawned.person_server_url.clone()),
        Some(&spawned.person_server_url),
        None,
        Some(on_clarification),
        None,
    );

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
    let spawned = spawn_test_server(ServerConfig {
        require_auth_token: true,
        with_auth_routes: true,
        federated: true,
        as_deferred_mode: true,
        ..Default::default()
    })
    .await;

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
                .header("content-type", "application/json")
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

    let client = build_client(
        &spawned,
        Some(spawned.person_server_url.clone()),
        Some(&spawned.person_server_url),
        Some(on_interaction),
        None,
        None,
    );

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

#[rstest]
#[timeout(Duration::from_secs(1))]
#[tokio::test]
async fn invalid_signature_rejected_over_http() {
    let spawned = spawn_test_server(ServerConfig {
        require_auth_token: false,
        with_auth_routes: false,
        ..Default::default()
    })
    .await;

    let wrong_keys = create_test_keys();
    let agent_jwt = mint_agent_jwt(
        &spawned.keys,
        &spawned.agent_url,
        AGENT_ID,
        Some(&spawned.person_server_url),
    );
    let provider = create_key_provider(&wrong_keys, agent_jwt);

    let client = build_client(&spawned, None, None, None, None, Some(provider));
    let response = client
        .get(format!("{}/api/data", spawned.resource_url))
        .send()
        .await
        .expect("request");

    assert_eq!(response.status(), reqwest::StatusCode::UNAUTHORIZED);
}
