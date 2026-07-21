//! `@aauth/fetch` CLI interop: local Person Server + hosted whoami resource.
//!
//! Prerequisites:
//! - `npx @aauth/bootstrap create <agent-provider-url>`
//! - `AAUTH_E2E_PUBLIC_BASE` — public URL of a tunnel fronting the local Person Server
//!
//! Run:
//! ```bash
//! cargo test -p aauth-axum --test fetch_person_server --features full -- --ignored --nocapture
//! ```

mod support;

use std::sync::Arc;

use aauth::TestKeys;

use support::apps::{PersonPolicyKind, person_server_app};
use support::fetch_cli::{
    FetchCliOptions, bootstrap_available, fetch_emit, public_base_url, whoami_url,
};
use support::listen::{bind, serve};
use support::metadata::MultiPartyMetadataFetcher;

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

    let keys = TestKeys::generate();
    let (listener, person_url) = bind().await;
    // Agent/resource URLs are unused for whoami; placeholders for the fetcher builder.
    let fetcher = MultiPartyMetadataFetcher::builder(&keys, &person_url, &person_url)
        .person_server(&person_url)
        .with_http_fallback()
        .build();
    let parts = person_server_app(
        &keys,
        &person_url,
        &whoami_url(),
        Arc::clone(&fetcher),
        PersonPolicyKind::Grant,
    );
    let person = serve(listener, parts.app, person_url);
    let person_server = person.url.clone();
    let _keep = person;

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
