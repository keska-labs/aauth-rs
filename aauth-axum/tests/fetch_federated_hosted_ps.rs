//! `@aauth/fetch` CLI interop: local Resource + hosted Person Server.
//!
//! Hosted `person.hello.coop` expects resource-token `aud` to be the Person Server
//! itself (three-party), not an Access Server — so this is PS-asserted against a
//! local resource, not four-party federation.
//!
//! Prerequisites:
//! - `npx @aauth/bootstrap create <agent-provider-url>`
//! - `AAUTH_E2E_PUBLIC_BASE` — tunnel fronting the local resource (hosted PS must
//!   fetch resource JWKS). When set, [`spawn_test_server`] advertises that base.
//!
//! Run:
//! ```bash
//! cargo test -p aauth-axum --test fetch_federated_hosted_ps --features full -- --ignored --nocapture
//! ```

mod support;

use support::axum_server::{TestScenario, spawn_test_server};
use support::fetch_cli::{
    FetchCliOptions, bootstrap_available, fetch_emit, hosted_person_server_url, public_base_url,
};

#[tokio::test]
#[ignore = "hybrid: needs bootstrap + AAUTH_E2E_PUBLIC_BASE + hosted PS consent"]
async fn fetch_local_resource_via_hosted_person_server() {
    assert!(
        bootstrap_available(),
        "missing @aauth/bootstrap config (AAUTH_DIR / ~/.aauth)"
    );
    assert!(
        public_base_url().is_some(),
        "set AAUTH_E2E_PUBLIC_BASE to a tunnel URL fronting the local test server"
    );

    let hosted_ps = hosted_person_server_url();
    let spawned = spawn_test_server(TestScenario::hosted_person_managed(hosted_ps.clone())).await;
    let resource_url = format!("{}/api/data", spawned.resource_url);
    let _keep = spawned;

    let emit = fetch_emit(
        &resource_url,
        FetchCliOptions::new()
            .person_server(hosted_ps)
            .browser()
            .poll_timeout_secs(900),
    )
    .await;

    let response = emit.response.expect("emit.response");
    assert_eq!(
        response.get("status").and_then(|v| v.as_str()),
        Some("ok"),
        "expected ok status: {response}"
    );
}
