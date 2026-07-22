//! Live E2E against [whoami.aauth.dev](https://whoami.aauth.dev) via `aauth-reqwest`.
//!
//! Prefer the `@aauth/fetch` CLI interop tests in `aauth-axum` (`fetch_person_server`)
//! when validating JS client ↔ Rust server. This suite keeps a Rust-client path.
//!
//! Prerequisites:
//! - `npx @aauth/bootstrap create <agent-provider-url>` with JWKS published
//! - Keys loadable via `aauth-local-keys` (`~/.aauth` / `AAUTH_DIR`, keychain, hardware)
//!
//! Run:
//! ```bash
//! cargo test -p aauth-reqwest --test whoami_e2e -- --ignored --nocapture
//! ```

use std::sync::Arc;

use aauth_local_keys::{list_agent_providers, person_server_url, LocalKeysProvider};
use aauth_reqwest::{AgentMiddleware, AgentOptions, CachedMetadataFetcher, ClientBuilder};
use serde_json::Value;

const WHOAMI: &str = "https://whoami.aauth.dev";
const WHOAMI_SCOPED: &str = "https://whoami.aauth.dev?scope=email+profile";

fn bootstrap_available() -> bool {
    !list_agent_providers().is_empty()
}

#[rstest::fixture]
#[once]
fn client() -> aauth_reqwest::ClientWithMiddleware {
    assert!(
        bootstrap_available(),
        "missing @aauth/bootstrap config (AAUTH_DIR / ~/.aauth). \
         Run `npx @aauth/bootstrap create <agent-provider-url>`."
    );

    let http = reqwest::Client::new();
    let provider = LocalKeysProvider::builder().build();
    let mut builder = AgentOptions::builder(provider)
        .metadata_fetcher(CachedMetadataFetcher::new(http.clone()))
        .on_interaction(Arc::new(|url, code| {
            eprintln!("Approve at: {url}?code={code}");
        }))
        .max_poll_duration_secs(900);

    if let Some(agent_url) = list_agent_providers().into_iter().next() {
        if let Some(ps) = person_server_url(&agent_url) {
            builder = builder.person_server_url(ps);
        }
    }

    ClientBuilder::new(http)
        .with(AgentMiddleware::new(builder.build()))
        .build()
}

#[rstest::rstest]
#[case::unscoped(WHOAMI)]
#[case::scoped(WHOAMI_SCOPED)]
#[tokio::test]
#[ignore = "live whoami; needs bootstrap + human consent"]
async fn whoami_agentic_fetch(client: &aauth_reqwest::ClientWithMiddleware, #[case] url: &str) {
    let response = client
        .get(url)
        .send()
        .await
        .unwrap_or_else(|e| panic!("request to {url} failed: {e}"));
    let status = response.status();
    let body = response
        .text()
        .await
        .unwrap_or_else(|e| panic!("reading body from {url}: {e}"));

    assert!(status.is_success(), "{url} returned {status}: {body}");
    let json: Value = serde_json::from_str(&body)
        .unwrap_or_else(|e| panic!("expected JSON from {url} ({e}): {body}"));

    assert!(
        json.get("sub").and_then(|v| v.as_str()).is_some(),
        "whoami response missing sub: {json}"
    );
}
