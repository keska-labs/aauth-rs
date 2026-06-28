mod support;

use std::sync::{Arc, Mutex, OnceLock};

use aauth::clear_metadata_cache;
use aauth::client::{create_aauth_fetch, AAuthFetchOptions};
use aauth::headers::{build_aauth_requirement, parse_aauth_requirement, AAuthRequirementParams};
use aauth::http::HttpRequest;
use aauth::metadata::CachedMetadataFetcher;
use aauth::server::{
    verify_token, InteractionManager, InteractionManagerOptions, VerifyTokenOptions,
};
use aauth::types::{AuthOkResponse, RequirementLevel, TokenExchangeRequest, TokenResponseBody};
use aauth::VerifiedToken;

use support::{
    create_agent_jwt, create_auth_jwt, create_key_provider, create_test_keys, MockServer,
    MockServerConfig,
};

const AGENT_URL: &str = "https://agent.example";
const AGENT_ID: &str = "aauth:test@example.com";
const AUTH_SERVER_URL: &str = "https://auth.example";
const RESOURCE_URL: &str = "https://resource.example";
const INTERACTION_URL: &str = "https://auth.example/interact";

fn test_lock() -> std::sync::MutexGuard<'static, ()> {
    static LOCK: OnceLock<Mutex<()>> = OnceLock::new();
    LOCK.get_or_init(|| Mutex::new(()))
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner())
}

#[tokio::test]
async fn aauth_requirement_header_round_trip_auth_token() {
    let _guard = test_lock();
    let header = build_aauth_requirement(
        RequirementLevel::AuthToken,
        Some(&AAuthRequirementParams {
            resource_token: Some("rt_abc123"),
            ..Default::default()
        }),
    )
    .unwrap();
    let parsed = parse_aauth_requirement(&header).unwrap();
    assert_eq!(parsed.requirement, RequirementLevel::AuthToken);
    assert_eq!(parsed.resource_token.as_deref(), Some("rt_abc123"));
}

#[tokio::test]
async fn aauth_requirement_header_round_trip_interaction() {
    let _guard = test_lock();
    let header = build_aauth_requirement(
        RequirementLevel::Interaction,
        Some(&AAuthRequirementParams {
            url: Some("https://auth.example/interact"),
            code: Some("CODE1234"),
            ..Default::default()
        }),
    )
    .unwrap();
    let parsed = parse_aauth_requirement(&header).unwrap();
    assert_eq!(parsed.requirement, RequirementLevel::Interaction);
    assert_eq!(parsed.url.as_deref(), Some("https://auth.example/interact"));
    assert_eq!(parsed.code.as_deref(), Some("CODE1234"));
}

#[tokio::test]
async fn aauth_requirement_header_round_trip_approval() {
    let _guard = test_lock();
    let header = build_aauth_requirement(RequirementLevel::Approval, None).unwrap();
    let parsed = parse_aauth_requirement(&header).unwrap();
    assert_eq!(parsed.requirement, RequirementLevel::Approval);
}

#[tokio::test]
async fn verify_token_agent_jwt() {
    let _guard = test_lock();
    clear_metadata_cache();
    let keys = create_test_keys();
    let agent_jwt = create_agent_jwt(&keys, AGENT_URL, AGENT_ID);

    let server = MockServer::new(mock_config(&keys, false, None, None, None));

    let fetcher =
        CachedMetadataFetcher::new(server.client.clone() as Arc<dyn aauth::http::HttpClient>);
    let result = verify_token(VerifyTokenOptions {
        jwt: agent_jwt,
        http_signature_thumbprint: keys.agent_ephemeral.thumbprint().to_string(),
        fetcher: Arc::new(fetcher),
    })
    .await
    .unwrap();

    match result {
        VerifiedToken::Agent(agent) => {
            assert_eq!(agent.iss, AGENT_URL);
            assert_eq!(agent.dwk, "aauth-agent.json");
            assert_eq!(agent.sub, AGENT_ID);
        }
        _ => panic!("expected agent token"),
    }
}

#[tokio::test]
async fn verify_token_auth_jwt() {
    let _guard = test_lock();
    clear_metadata_cache();
    let keys = create_test_keys();
    let auth_jwt = create_auth_jwt(
        &keys,
        AUTH_SERVER_URL,
        RESOURCE_URL,
        AGENT_URL,
        Some("user-456"),
        Some("files.read"),
    );

    let server = MockServer::new(mock_config(&keys, false, None, None, None));

    let fetcher =
        CachedMetadataFetcher::new(server.client.clone() as Arc<dyn aauth::http::HttpClient>);
    let result = verify_token(VerifyTokenOptions {
        jwt: auth_jwt,
        http_signature_thumbprint: keys.agent_ephemeral.thumbprint().to_string(),
        fetcher: Arc::new(fetcher),
    })
    .await
    .unwrap();

    match result {
        VerifiedToken::Auth(auth) => {
            assert_eq!(auth.iss, AUTH_SERVER_URL);
            assert_eq!(auth.dwk, "aauth-person.json");
            assert_eq!(auth.agent, AGENT_URL);
            assert_eq!(auth.sub.as_deref(), Some("user-456"));
            assert_eq!(auth.scope.as_deref(), Some("files.read"));
        }
        _ => panic!("expected auth token"),
    }
}

#[tokio::test]
async fn verify_token_key_binding_failed() {
    let _guard = test_lock();
    clear_metadata_cache();
    let keys = create_test_keys();
    let agent_jwt = create_agent_jwt(&keys, AGENT_URL, AGENT_ID);
    let wrong = create_test_keys();

    let server = MockServer::new(mock_config(&keys, false, None, None, None));

    let fetcher =
        CachedMetadataFetcher::new(server.client.clone() as Arc<dyn aauth::http::HttpClient>);
    let err = verify_token(VerifyTokenOptions {
        jwt: agent_jwt,
        http_signature_thumbprint: wrong.agent_ephemeral.thumbprint().to_string(),
        fetcher: Arc::new(fetcher),
    })
    .await
    .unwrap_err();

    assert!(err
        .to_string()
        .contains("cnf.jwk thumbprint does not match"));
}

#[tokio::test]
async fn full_401_challenge_response_direct_grant() {
    let _guard = test_lock();
    clear_metadata_cache();
    let keys = create_test_keys();
    let agent_jwt = create_agent_jwt(&keys, AGENT_URL, AGENT_ID);
    let provider = create_key_provider(&keys, agent_jwt);

    let server = MockServer::new(mock_config(&keys, false, None, None, None));
    let fetch = aauth_fetch(provider, server.client.clone(), None, None);

    let response = fetch
        .fetch(
            &format!("{RESOURCE_URL}/api/data"),
            HttpRequest {
                method: "GET".into(),
                url: format!("{RESOURCE_URL}/api/data"),
                headers: Default::default(),
                body: None,
            },
        )
        .await
        .unwrap();

    assert_eq!(response.status, 200);
    let body: AuthOkResponse = response.json().unwrap();
    assert_eq!(body.status, "ok");
    assert_eq!(body.user.as_deref(), Some("user-123"));
}

#[tokio::test]
async fn second_request_reuses_cached_token() {
    let _guard = test_lock();
    clear_metadata_cache();
    let keys = create_test_keys();
    let agent_jwt = create_agent_jwt(&keys, AGENT_URL, AGENT_ID);
    let provider = create_key_provider(&keys, agent_jwt);

    let call_count = Arc::new(Mutex::new(0usize));
    let server = MockServer::new(mock_config(&keys, false, None, None, None));
    let counting_client = Arc::new(CountingClient {
        inner: server.client.clone(),
        count: Arc::clone(&call_count),
    });

    let fetch = aauth_fetch(provider, counting_client, None, None);

    let req = |path: &str| HttpRequest {
        method: "GET".into(),
        url: format!("{RESOURCE_URL}{path}"),
        headers: Default::default(),
        body: None,
    };

    let _ = fetch
        .fetch(&req("/api/data").url, req("/api/data"))
        .await
        .unwrap();
    let after_first = *call_count.lock().unwrap();
    let _ = fetch
        .fetch(&req("/api/other").url, req("/api/other"))
        .await
        .unwrap();
    let after_second = *call_count.lock().unwrap();

    assert!(after_first >= 4);
    assert_eq!(after_second - after_first, 1);
}

#[tokio::test]
async fn justification_and_hints_pass_through() {
    let _guard = test_lock();
    clear_metadata_cache();
    let keys = create_test_keys();
    let agent_jwt = create_agent_jwt(&keys, AGENT_URL, AGENT_ID);
    let provider = create_key_provider(&keys, agent_jwt);
    let captured = Arc::new(Mutex::new(None));

    let server = MockServer::new(mock_config(
        &keys,
        false,
        None,
        Some(Arc::clone(&captured)),
        None,
    ));

    let fetch = aauth_fetch(
        provider,
        server.client.clone(),
        Some("read user files".into()),
        Some((
            "alice@acme.com".into(),
            "acme.com".into(),
            "acme.com".into(),
        )),
    );

    let _ = fetch
        .fetch(
            &format!("{RESOURCE_URL}/api/data"),
            HttpRequest {
                method: "GET".into(),
                url: format!("{RESOURCE_URL}/api/data"),
                headers: Default::default(),
                body: None,
            },
        )
        .await
        .unwrap();

    let body = captured.lock().unwrap().clone().expect("captured body");
    assert!(!body.resource_token.is_empty());
    assert_eq!(body.justification.as_deref(), Some("read user files"));
    assert_eq!(body.login_hint.as_deref(), Some("alice@acme.com"));
    assert_eq!(body.tenant.as_deref(), Some("acme.com"));
    assert_eq!(body.domain_hint.as_deref(), Some("acme.com"));
}

#[tokio::test]
async fn deferred_interaction_grant() {
    let _guard = test_lock();
    clear_metadata_cache();
    let keys = create_test_keys();
    let agent_jwt = create_agent_jwt(&keys, AGENT_URL, AGENT_ID);
    let provider = create_key_provider(&keys, agent_jwt);

    let manager = Arc::new(InteractionManager::new(InteractionManagerOptions {
        base_url: AUTH_SERVER_URL.into(),
        interaction_url: INTERACTION_URL.into(),
        pending_path: None,
        ttl: None,
    }));
    let pending_id_capture = Arc::new(Mutex::new(None));

    let server = MockServer::new(mock_config(
        &keys,
        true,
        Some(Arc::clone(&manager)),
        None,
        Some(Arc::clone(&pending_id_capture)),
    ));

    let received = Arc::new(Mutex::new(None));
    let received_cb = Arc::clone(&received);
    let manager_cb = Arc::clone(&manager);
    let keys_cb = keys.clone();
    let pending_id_capture_cb = Arc::clone(&pending_id_capture);

    let on_interaction: aauth::InteractionCallback = Arc::new(move |url, code| {
        *received_cb.lock().unwrap() = Some((url.clone(), code.clone()));
        if let Some(id) = pending_id_capture_cb.lock().unwrap().clone() {
            let auth_jwt = create_auth_jwt(
                &keys_cb,
                AUTH_SERVER_URL,
                RESOURCE_URL,
                AGENT_URL,
                Some("user-deferred"),
                None,
            );
            let _ = manager_cb.resolve(
                &id,
                TokenResponseBody {
                    auth_token: auth_jwt,
                    expires_in: 3600,
                },
            );
        }
    });

    let fetch = create_aauth_fetch(AAuthFetchOptions {
        provider,
        client: server.client.clone(),
        auth_server_url: Some(AUTH_SERVER_URL.into()),
        auth_server_metadata: None,
        on_metadata: None,
        on_auth_token: None,
        on_opaque_token: None,
        opaque_token: None,
        on_interaction: Some(on_interaction),
        on_clarification: None,
        justification: None,
        login_hint: None,
        tenant: None,
        domain_hint: None,
        capabilities: None,
        mission: None,
        prompt: None,
    });

    let response = fetch
        .fetch(
            &format!("{RESOURCE_URL}/api/data"),
            HttpRequest {
                method: "GET".into(),
                url: format!("{RESOURCE_URL}/api/data"),
                headers: Default::default(),
                body: None,
            },
        )
        .await
        .unwrap();

    assert_eq!(response.status, 200);
    let interaction = received.lock().unwrap().clone();
    assert!(interaction.is_some());
    let (url, code) = interaction.unwrap();
    assert_eq!(url, INTERACTION_URL);
    assert!(!code.is_empty());
}

#[tokio::test]
async fn interaction_manager_create_pending_header() {
    let _guard = test_lock();
    let manager = InteractionManager::new(InteractionManagerOptions {
        base_url: AUTH_SERVER_URL.into(),
        interaction_url: INTERACTION_URL.into(),
        pending_path: None,
        ttl: None,
    });
    let (headers, pending) = manager.create_pending();
    assert!(pending.code.contains('-'));
    assert!(headers["Location"].contains("/pending/"));
    assert!(headers["AAuth-Requirement"].contains("requirement=interaction"));
    assert!(headers["AAuth-Requirement"].contains(&format!("url=\"{INTERACTION_URL}\"")));
    assert!(headers["AAuth-Requirement"].contains(&format!("code=\"{}\"", pending.code)));

    let parsed = parse_aauth_requirement(&headers["AAuth-Requirement"]).unwrap();
    assert_eq!(parsed.requirement, RequirementLevel::Interaction);
    assert_eq!(parsed.url.as_deref(), Some(INTERACTION_URL));
    assert_eq!(parsed.code.as_deref(), Some(pending.code.as_str()));
}

fn mock_config(
    keys: &support::TestKeys,
    deferred_mode: bool,
    interaction_manager: Option<Arc<InteractionManager>>,
    on_token_request: Option<Arc<Mutex<Option<TokenExchangeRequest>>>>,
    pending_id_capture: Option<Arc<Mutex<Option<String>>>>,
) -> MockServerConfig {
    MockServerConfig {
        keys: keys.clone(),
        resource_url: RESOURCE_URL.into(),
        auth_server_url: AUTH_SERVER_URL.into(),
        agent_url: AGENT_URL.into(),
        sub: AGENT_ID.into(),
        require_auth_token: true,
        deferred_mode,
        interaction_manager,
        on_token_request,
        pending_id_capture,
    }
}

fn aauth_fetch(
    provider: Arc<dyn aauth::client::KeyMaterialProvider>,
    client: Arc<dyn aauth::client::HttpClientAdapter>,
    justification: Option<String>,
    hints: Option<(String, String, String)>,
) -> aauth::client::AAuthFetch {
    let (login_hint, tenant, domain_hint) = hints
        .map(|(l, t, d)| (Some(l), Some(t), Some(d)))
        .unwrap_or((None, None, None));

    create_aauth_fetch(AAuthFetchOptions {
        provider,
        client,
        auth_server_url: Some(AUTH_SERVER_URL.into()),
        auth_server_metadata: None,
        on_metadata: None,
        on_auth_token: None,
        on_opaque_token: None,
        opaque_token: None,
        on_interaction: None,
        on_clarification: None,
        justification,
        login_hint,
        tenant,
        domain_hint,
        capabilities: None,
        mission: None,
        prompt: None,
    })
}

struct CountingClient {
    inner: Arc<support::MockHttpClient>,
    count: Arc<Mutex<usize>>,
}

#[async_trait::async_trait]
impl aauth::client::HttpClientAdapter for CountingClient {
    async fn send(
        &self,
        request: aauth::http::HttpRequest,
    ) -> aauth::error::Result<aauth::http::HttpResponse> {
        *self.count.lock().unwrap() += 1;
        self.inner.send(request).await
    }
}
