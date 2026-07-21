//! `@aauth/fetch` CLI interop: local Resource + hosted Person Server.
//!
//! Hosted `person.hello.coop` expects resource-token `aud` to be the Person Server
//! itself (three-party), not an Access Server — so this is PS-asserted against a
//! local resource, not four-party federation.
//!
//! Prerequisites:
//! - `npx @aauth/bootstrap create <agent-provider-url>`
//! - `AAUTH_E2E_PUBLIC_BASE` — tunnel fronting the local resource (hosted PS must
//!   fetch resource JWKS).
//!
//! Run:
//! ```bash
//! cargo test -p aauth-axum --test fetch_federated_hosted_ps --features full -- --ignored --nocapture
//! ```

mod support;

use std::sync::Arc;

use aauth::TestKeys;

use support::apps::hosted_person_managed_resource_app;
use support::fetch_cli::{
    FetchCliOptions, bootstrap_available, fetch_emit, hosted_person_server_url, public_base_url,
};
use support::listen::{bind, serve};
use support::metadata::MultiPartyMetadataFetcher;

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
    let keys = TestKeys::generate();
    let (listener, resource_url) = bind().await;
    let fetcher = MultiPartyMetadataFetcher::builder(&keys, &resource_url, &resource_url)
        .with_http_fallback()
        .build();
    let resource = serve(
        listener,
        hosted_person_managed_resource_app(&keys, &resource_url, &hosted_ps, Arc::clone(&fetcher)),
        resource_url,
    );
    let resource_api = format!("{}/api/data", resource.url);
    let _keep = resource;

    let emit = fetch_emit(
        &resource_api,
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
