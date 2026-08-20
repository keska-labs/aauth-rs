//! Live E2E against [whoami.aauth.dev](https://whoami.aauth.dev) via `aauth-reqwest`.
//!
//! Mirrors the two-call walkthrough in `docs/e2e-prompt.md` / `@aauth/fetch`:
//! 1. Unscoped — identity-based (agent JWT only; no person-server / consent)
//! 2. Scoped — three-party with `prompt=consent` so approval is required even when
//!    consent is already on file at the person server (same as `--prompt-consent`)
//!
//! Prefer the `@aauth/fetch` CLI interop tests in `aauth-axum` (`fetch_person_server`)
//! when validating JS client ↔ Rust server. This suite keeps a Rust-client path.
//!
//! Prerequisites:
//! - `npx @aauth/bootstrap create <agent-provider-url>` with JWKS published
//! - Keys loadable via `aauth-local-keys` (`~/.aauth` / `AAUTH_DIR`, keychain, hardware)
//! - For the scoped case: approve the printed URL (person server interaction)
//!
//! Run:
//! ```bash
//! cargo test -p aauth-reqwest --test whoami_e2e -- --ignored --nocapture
//! ```

use std::sync::Arc;

use aauth::Capability;
use aauth_local_keys::{list_agent_providers, person_server_url, LocalKeysProvider};
use aauth_reqwest::{AgentMiddleware, AgentOptions, CachedMetadataFetcher, ClientBuilder};
use serde_json::Value;

const WHOAMI: &str = "https://whoami.aauth.dev";
const WHOAMI_SCOPED: &str = "https://whoami.aauth.dev?scope=email+profile";

fn bootstrap_available() -> bool {
    !list_agent_providers().is_empty()
}

fn build_client(prompt_consent: bool) -> aauth_reqwest::ClientWithMiddleware {
    assert!(
        bootstrap_available(),
        "missing @aauth/bootstrap config (AAUTH_DIR / ~/.aauth). \
         Run `npx @aauth/bootstrap create <agent-provider-url>`."
    );

    let http = reqwest::Client::new();
    let provider = LocalKeysProvider::builder().build();
    let mut builder = AgentOptions::builder(provider)
        .metadata_fetcher(CachedMetadataFetcher::new(http.clone()))
        .capabilities(vec![Capability::Interaction])
        .on_interaction(Arc::new(|url, code| {
            eprintln!("Approve at: {url}?code={code}");
        }))
        .max_poll_duration_secs(900);

    if prompt_consent {
        // OIDC-style force-consent; without this, person.hello.coop returns 200 when
        // consent is already on file and the scoped case never surfaces an approval URL.
        builder = builder.prompt("consent");
    }

    if let Some(agent_url) = list_agent_providers().into_iter().next() {
        if let Some(ps) = person_server_url(&agent_url) {
            builder = builder.person_server_url(ps);
        }
    }

    ClientBuilder::new(http)
        .with(AgentMiddleware::new(builder.build()))
        .build()
}

#[tokio::test]
#[ignore = "live whoami; needs bootstrap"]
async fn whoami_identity_based() {
    let client = build_client(false);
    let response = client
        .get(WHOAMI)
        .send()
        .await
        .unwrap_or_else(|e| panic!("request to {WHOAMI} failed: {e}"));
    let status = response.status();
    let body = response
        .text()
        .await
        .unwrap_or_else(|e| panic!("reading body from {WHOAMI}: {e}"));

    assert!(status.is_success(), "{WHOAMI} returned {status}: {body}");
    let json: Value = serde_json::from_str(&body)
        .unwrap_or_else(|e| panic!("expected JSON from {WHOAMI} ({e}): {body}"));

    let sub = json
        .get("sub")
        .and_then(|v| v.as_str())
        .unwrap_or_else(|| panic!("whoami identity response missing sub: {json}"));
    assert!(
        sub.starts_with("aauth:"),
        "identity-based whoami should echo the agent id as sub, got {json}"
    );
    assert!(
        json.get("email").is_none(),
        "identity-based whoami should not include person claims: {json}"
    );
}

#[tokio::test]
#[ignore = "live whoami; needs bootstrap + human consent (prompt=consent)"]
async fn whoami_scoped_requires_consent() {
    let client = build_client(true);
    let response = client
        .get(WHOAMI_SCOPED)
        .send()
        .await
        .unwrap_or_else(|e| panic!("request to {WHOAMI_SCOPED} failed: {e}"));
    let status = response.status();
    let body = response
        .text()
        .await
        .unwrap_or_else(|e| panic!("reading body from {WHOAMI_SCOPED}: {e}"));

    assert!(
        status.is_success(),
        "{WHOAMI_SCOPED} returned {status}: {body}"
    );
    let json: Value = serde_json::from_str(&body)
        .unwrap_or_else(|e| panic!("expected JSON from {WHOAMI_SCOPED} ({e}): {body}"));

    assert!(
        json.get("sub").and_then(|v| v.as_str()).is_some(),
        "scoped whoami response missing person sub: {json}"
    );
    assert!(
        json.get("agent").and_then(|v| v.as_str()).is_some(),
        "scoped whoami should include agent claim from auth token: {json}"
    );
    assert!(
        json.get("email").and_then(|v| v.as_str()).is_some()
            || json.get("name").and_then(|v| v.as_str()).is_some(),
        "scoped whoami should include person claims (email/name): {json}"
    );
}
