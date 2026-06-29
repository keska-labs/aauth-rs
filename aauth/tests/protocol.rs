mod support;

use std::sync::{Arc, Mutex, OnceLock};

use aauth::KeyMaterialProvider;
use aauth::VerifiedToken;
use aauth::client::reqwest::{
    AgentOptions, AgentMiddleware, ClientBuilder, InteractionCallback,
};
use aauth::headers::{AAuthRequirementParams, build_aauth_requirement, parse_aauth_requirement};
use aauth::server::{
    DeferRequirement, VerifyTokenOptions, build_accepted, verify_token,
};
use aauth::types::{AuthOkResponse, RequirementLevel, TokenExchangeRequest, TokenResponseBody};
use aauth::{InMemoryPendingStore, PendingOutcome, PendingStore};
use http::Extensions;
use reqwest::{Request, Response};
use reqwest_middleware::{Error, Middleware, Next};

use aauth::{
    TestKeys, create_key_provider, create_test_keys, mint_agent_jwt, mint_auth_jwt,
    static_agent_metadata_fetcher, static_person_metadata_fetcher,
};

use support::{MockServer, MockServerConfig, MockTransport};

const AGENT_URL: &str = "https://agent.example";
const AGENT_ID: &str = "aauth:test@example.com";
const PERSON_SERVER_URL: &str = "https://person.example";
const RESOURCE_URL: &str = "https://resource.example";
const INTERACTION_URL: &str = "https://person.example/interact";

fn test_lock() -> std::sync::MutexGuard<'static, ()> {
    static LOCK: OnceLock<Mutex<()>> = OnceLock::new();
    LOCK.get_or_init(|| Mutex::new(()))
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner())
}

fn build_client(
    options: AgentOptions,
    server: &MockServer,
) -> aauth::client::reqwest::ClientWithMiddleware {
    ClientBuilder::new(reqwest::Client::new())
        .with(AgentMiddleware::new(options))
        .with(server.mock_transport())
        .build()
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
    let keys = create_test_keys();
    let agent_jwt = mint_agent_jwt(&keys, AGENT_URL, AGENT_ID, Some(PERSON_SERVER_URL));

    let fetcher = static_agent_metadata_fetcher(&keys, AGENT_URL);
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
    let keys = create_test_keys();
    let auth_jwt = mint_auth_jwt(
        &keys,
        PERSON_SERVER_URL,
        RESOURCE_URL,
        AGENT_URL,
        Some("user-456"),
        Some("files.read"),
    );

    let fetcher = static_person_metadata_fetcher(&keys, PERSON_SERVER_URL);
    let result = verify_token(VerifyTokenOptions {
        jwt: auth_jwt,
        http_signature_thumbprint: keys.agent_ephemeral.thumbprint().to_string(),
        fetcher: Arc::new(fetcher),
    })
    .await
    .unwrap();

    match result {
        VerifiedToken::Auth(auth) => {
            assert_eq!(auth.iss, PERSON_SERVER_URL);
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
    let keys = create_test_keys();
    let agent_jwt = mint_agent_jwt(&keys, AGENT_URL, AGENT_ID, Some(PERSON_SERVER_URL));
    let wrong = create_test_keys();

    let fetcher = static_agent_metadata_fetcher(&keys, AGENT_URL);
    let err = verify_token(VerifyTokenOptions {
        jwt: agent_jwt,
        http_signature_thumbprint: wrong.agent_ephemeral.thumbprint().to_string(),
        fetcher: Arc::new(fetcher),
    })
    .await
    .unwrap_err();

    assert!(
        err.to_string()
            .contains("cnf.jwk thumbprint does not match")
    );
}

#[tokio::test]
async fn full_401_challenge_response_direct_grant() {
    let _guard = test_lock();
    let keys = create_test_keys();
    let agent_jwt = mint_agent_jwt(&keys, AGENT_URL, AGENT_ID, Some(PERSON_SERVER_URL));
    let provider = create_key_provider(&keys, agent_jwt);

    let server = MockServer::new(mock_config(&keys, false, None, None));
    let client = aauth_client(provider, &server, None, None);

    let response = client
        .get(format!("{RESOURCE_URL}/api/data"))
        .send()
        .await
        .unwrap();

    assert_eq!(response.status(), 200);
    let body: AuthOkResponse = response.json().await.unwrap();
    assert_eq!(body.status, "ok");
    assert_eq!(body.user.as_deref(), Some("user-123"));
}

#[tokio::test]
async fn second_request_reuses_cached_token() {
    let _guard = test_lock();
    let keys = create_test_keys();
    let agent_jwt = mint_agent_jwt(&keys, AGENT_URL, AGENT_ID, Some(PERSON_SERVER_URL));
    let provider = create_key_provider(&keys, agent_jwt);

    let call_count = Arc::new(Mutex::new(0usize));
    let server = MockServer::new(mock_config(&keys, false, None, None));

    let options = aauth_options(provider, None, None);
    let client = ClientBuilder::new(reqwest::Client::new())
        .with(AgentMiddleware::new(options))
        .with(CountingMiddleware {
            count: Arc::clone(&call_count),
        })
        .with(server.mock_transport())
        .build();

    let _ = client
        .get(format!("{RESOURCE_URL}/api/data"))
        .send()
        .await
        .unwrap();
    let after_first = *call_count.lock().unwrap();
    let _ = client
        .get(format!("{RESOURCE_URL}/api/other"))
        .send()
        .await
        .unwrap();
    let after_second = *call_count.lock().unwrap();

    assert!(after_first >= 4);
    assert_eq!(after_second - after_first, 1);
}

#[tokio::test]
async fn justification_and_hints_pass_through() {
    let _guard = test_lock();
    let keys = create_test_keys();
    let agent_jwt = mint_agent_jwt(&keys, AGENT_URL, AGENT_ID, Some(PERSON_SERVER_URL));
    let provider = create_key_provider(&keys, agent_jwt);
    let captured = Arc::new(Mutex::new(None));

    let server = MockServer::new(mock_config(
        &keys,
        false,
        None,
        Some(Arc::clone(&captured)),
    ));

    let client = aauth_client(
        provider,
        &server,
        Some("read user files".into()),
        Some((
            "alice@acme.com".into(),
            "acme.com".into(),
            "acme.com".into(),
        )),
    );

    let _ = client
        .get(format!("{RESOURCE_URL}/api/data"))
        .send()
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
    let keys = create_test_keys();
    let agent_jwt = mint_agent_jwt(&keys, AGENT_URL, AGENT_ID, Some(PERSON_SERVER_URL));
    let provider = create_key_provider(&keys, agent_jwt);

    let pending = InMemoryPendingStore::new();

    let server = MockServer::new(mock_config(
        &keys,
        true,
        Some(pending.clone()),
        None,
    ));

    let received = Arc::new(Mutex::new(None));
    let received_cb = Arc::clone(&received);
    let pending_cb = pending.clone();
    let keys_cb = keys.clone();

    let on_interaction: InteractionCallback = Arc::new(move |url, code| {
        *received_cb.lock().unwrap() = Some((url.clone(), code.clone()));
        if let Some(id) = pending_cb.last_created.lock().unwrap().clone() {
            let auth_jwt = mint_auth_jwt(
                &keys_cb,
                PERSON_SERVER_URL,
                RESOURCE_URL,
                AGENT_URL,
                Some("user-deferred"),
                None,
            );
            let pending = pending_cb.clone();
            tokio::spawn(async move {
                let _ = pending
                    .complete(
                        &id,
                        PendingOutcome::AuthToken(TokenResponseBody {
                            auth_token: auth_jwt,
                            expires_in: 3600,
                        }),
                    )
                    .await;
            });
        }
    });

    let options = AgentOptions::builder(Arc::clone(&provider))
        .person_server_url(PERSON_SERVER_URL)
        .on_interaction(on_interaction)
        .max_poll_duration_secs(5)
        .build();
    let client = build_client(options, &server);

    let response = client
        .get(format!("{RESOURCE_URL}/api/data"))
        .send()
        .await
        .unwrap();

    assert_eq!(response.status(), 200);
    let interaction = received.lock().unwrap().clone();
    assert!(interaction.is_some());
    let (url, code) = interaction.unwrap();
    assert_eq!(url, INTERACTION_URL);
    assert!(!code.is_empty());
}

#[tokio::test]
async fn deferred_accepted_response_format() {
    let _guard = test_lock();
    let code = aauth::interaction_code::generate_code();
    let requirement = DeferRequirement::Interaction {
        url: INTERACTION_URL.into(),
        code: code.clone(),
    };
    let accepted = build_accepted("https://person.example/pending/abc", &requirement).unwrap();
    assert_eq!(accepted.status, http::StatusCode::ACCEPTED);
    assert_eq!(
        accepted.headers.get("Location").unwrap(),
        "https://person.example/pending/abc"
    );
    let aauth_req = accepted.headers.get("AAuth-Requirement").unwrap().to_str().unwrap();
    let parsed = parse_aauth_requirement(aauth_req).unwrap();
    assert_eq!(parsed.requirement, RequirementLevel::Interaction);
    assert_eq!(parsed.url.as_deref(), Some(INTERACTION_URL));
    assert_eq!(parsed.code.as_deref(), Some(code.as_str()));
}

fn mock_config(
    keys: &TestKeys,
    deferred_mode: bool,
    pending: Option<InMemoryPendingStore>,
    on_token_request: Option<Arc<Mutex<Option<TokenExchangeRequest>>>>,
) -> MockServerConfig {
    MockServerConfig {
        keys: keys.clone(),
        resource_url: RESOURCE_URL.into(),
        person_server_url: PERSON_SERVER_URL.into(),
        agent_url: AGENT_URL.into(),
        sub: AGENT_ID.into(),
        require_auth_token: true,
        deferred_mode,
        pending,
        on_token_request,
    }
}

fn aauth_options(
    provider: Arc<dyn KeyMaterialProvider>,
    justification: Option<String>,
    hints: Option<(String, String, String)>,
) -> AgentOptions {
    let mut builder = AgentOptions::builder(provider)
        .person_server_url(PERSON_SERVER_URL)
        .max_poll_duration_secs(5);
    if let Some(justification) = justification {
        builder = builder.justification(justification);
    }
    if let Some((login_hint, tenant, domain_hint)) = hints {
        builder = builder
            .login_hint(login_hint)
            .tenant(tenant)
            .domain_hint(domain_hint);
    }
    builder.build()
}

fn aauth_client(
    provider: Arc<dyn KeyMaterialProvider>,
    server: &MockServer,
    justification: Option<String>,
    hints: Option<(String, String, String)>,
) -> aauth::client::reqwest::ClientWithMiddleware {
    build_client(
        aauth_options(Arc::clone(&provider), justification, hints),
        server,
    )
}

struct CountingMiddleware {
    count: Arc<Mutex<usize>>,
}

#[async_trait::async_trait]
impl Middleware for CountingMiddleware {
    async fn handle(
        &self,
        req: Request,
        extensions: &mut Extensions,
        next: Next<'_>,
    ) -> std::result::Result<Response, Error> {
        *self.count.lock().unwrap() += 1;
        next.run(req, extensions).await
    }
}
