//! `@aauth/fetch` CLI interop: local Person Server + hosted whoami resource.
//!
//! Prerequisites:
//! - `npx @aauth/bootstrap create <agent-provider-url>`
//! - `AAUTH_E2E_PUBLIC_BASE` — public URL of a tunnel fronting the local listener
//!   (hosted whoami must fetch JWKS from the local Person Server). When set,
//!   [`spawn_test_server`](support::axum_server::spawn_test_server) advertises that base.
//!
//! Run:
//! ```bash
//! cargo test -p aauth-axum --test fetch_person_server --features full -- --ignored --nocapture
//! ```

mod support;

use support::axum_server::{TestScenario, spawn_test_server};
use support::fetch_cli::{
    FetchCliOptions, bootstrap_available, fetch_emit, public_base_url, whoami_url,
};

#[tokio::test]
#[ignore = "hybrid: needs bootstrap + AAUTH_E2E_PUBLIC_BASE tunnel to local PS"]
async fn fetch_whoami_via_local_person_server() {
    assert!(
        bootstrap_available(),
        "missing @aauth/bootstrap config (AAUTH_DIR / ~/.aauth)"
    );
    assert!(
        public_base_url().is_some(),
        "set AAUTH_E2E_PUBLIC_BASE to a tunnel URL fronting the local test server"
    );

    let spawned = spawn_test_server(TestScenario::person_managed()).await;
    let person_server = spawned.person_server_url.clone();
    let _keep = spawned;

    let emit = fetch_emit(
        &whoami_url(),
        FetchCliOptions::new()
            .person_server(person_server)
            .non_interactive()
            .poll_timeout_secs(60),
    )
    .await;

    let response = emit.response.expect("emit.response");
    assert!(
        response.get("sub").and_then(|v| v.as_str()).is_some(),
        "whoami response missing sub: {response}"
    );
}
