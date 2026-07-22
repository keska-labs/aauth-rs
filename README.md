# aauth-rs

Rust implementation of the [AAuth authorization protocol](https://github.com/dickhardt/AAuth).

AAuth lets an **agent** present a signed identity to a **resource**, and — when needed — obtain authorization from a **Person Server** (and optionally an **Access Server**) before the resource grants access. This workspace is a pre-alpha Rust port aimed at protocol parity with the [reference TypeScript packages](https://github.com/aauth-dev/packages-js).

## Status

**Pre-alpha.** The API and behavior are unstable. We are still aligning with the draft and the JS reference; expect breaking changes. Contributions are not useful yet — check back after the next round of internal work.

## Protocol in one glance

```text
Agent ──signed request──▶ Resource
Agent ◀──401 + AAuth-Requirement── Resource   (when more than identity is required)
Agent ──POST /token──▶ Person Server (+ Access Server if federated)
Agent ──signed request + auth/opaque token──▶ Resource
Agent ◀──200── Resource
```

Access modes (identity-based, Person Server managed, resource-managed, federated) are compared in the [AAuth Protocol Explorer](https://explorer.aauth.dev/access/compare).

Canonical spec: [`docs/specs/draft-hardt-oauth-aauth-protocol.md`](./docs/specs/draft-hardt-oauth-aauth-protocol.md).

## Crates

| Crate | Role | docs.rs |
|-------|------|---------|
| [`aauth`](./aauth/) | Protocol types, JWT/signature helpers, role service traits, agent state machine | [docs.rs/aauth](https://docs.rs/aauth) |
| [`aauth-reqwest`](./aauth-reqwest/) | Agent HTTP client (`AgentMiddleware` on reqwest) | [docs.rs/aauth-reqwest](https://docs.rs/aauth-reqwest) |
| [`aauth-axum`](./aauth-axum/) | Server HTTP adapters (routers, `ResourceAuthLayer`) | [docs.rs/aauth-axum](https://docs.rs/aauth-axum) |
| [`aauth-policy`](./aauth-policy/) | Opinionated policy traits, pending stores, and `Policy*Service` helpers | [docs.rs/aauth-policy](https://docs.rs/aauth-policy) |
| [`httpsig-key`](./httpsig-key/) | HTTP Signature Keys (`Signature-Key`) on top of [`httpsig`](https://crates.io/crates/httpsig) | [docs.rs/httpsig-key](https://docs.rs/httpsig-key) |

Pick crates by what you implement:

- **Agent client** → `aauth` (`agent`) + `aauth-reqwest`
- **Person / Access / Resource server** → `aauth` (role feature) + `aauth-axum` (matching feature); optionally `aauth-policy` for a batteries-included service
- **Wire / crypto only** → `aauth` protocol modules, or `httpsig-key` alone

Each crate’s README is the rustdoc crate page (`#![doc = include_str!(…)]`). The Rust snippets below are doctests (run via `cargo test -p aauth-axum --doc --features full`).

## Repository layout

```text
aauth-rs/
├── aauth/           # core protocol + role traits
├── aauth-reqwest/   # reqwest agent transport
├── aauth-axum/      # axum server adapters + examples
├── aauth-policy/    # policy + pending-store services
├── httpsig-key/     # Signature-Key (RFC 9421 companion draft)
└── docs/specs/      # protocol drafts used as source of truth
```

## Usage

### Agent (reqwest)

```toml
aauth = { version = "0.0", default-features = false, features = ["agent"] }
aauth-reqwest = { version = "0.0" }
```

```rust,no_run
#![cfg(feature = "full")]
use aauth::TestKeys;
use aauth_reqwest::{AgentMiddleware, AgentOptions, ClientBuilder};

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let keys = TestKeys::generate();
    let issuer = "https://example.com";
    let agent_jwt = keys.mint_agent_jwt(issuer, "aauth:test@example.com", None);

    let client = ClientBuilder::new(reqwest::Client::new())
        .with(AgentMiddleware::new(
            AgentOptions::builder(keys.key_provider(agent_jwt))
                .metadata_fetcher(keys.agent_metadata_fetcher(issuer))
                // person_server_url omitted → resolved from agent JWT `ps` when challenged
                .build(),
        ))
        .build();

    // Signing + challenge handling are automatic.
    let identity = client
        .get("https://whoami.aauth.dev")
        .send()
        .await?
        .text()
        .await?;
    println!("{identity}");

    let scoped = client
        .get("https://whoami.aauth.dev?scope=openid+profile")
        .send()
        .await?
        .text()
        .await?;
    println!("{scoped}");
    Ok(())
}
```

### Resource server (axum)

Protect routes with `ResourceAuthLayer`; handlers read `VerifiedAAuthToken`. Switch `ResourceAccessMode` for identity-based, Person Server managed, federated, or resource-managed.

```toml
aauth = { version = "0.0", default-features = false, features = ["resource"] }
aauth-axum = { version = "0.0", default-features = false, features = ["resource"] }
```

```rust
#![cfg(feature = "resource")]
use std::sync::Arc;

use aauth::protocol::{SignatureKey, SignatureKeyJwt, SigningMaterial};
use aauth::{NoResourceAccessService, RequestSigningExt, ResourceAccessMode, TestKeys};
use aauth_axum::{ResourceAuthLayer, VerifiedAAuthToken};
use axum::body::Body;
use axum::http::{HeaderValue, Request, StatusCode, header::HOST};
use axum::{Json, Router, routing::get};
use tower::ServiceExt;

#[tokio::main]
async fn main() {
    let keys = TestKeys::generate();
    let issuer = "https://example.com";

    let layer = ResourceAuthLayer::new(
        keys.agent_metadata_fetcher(issuer),
        "http://resource.example",
        ResourceAccessMode::<NoResourceAccessService>::IdentityBased,
        Arc::new(keys.resource_token_signer()),
    );

    let app = Router::new()
        .route(
            "/api/data",
            get(|_token: VerifiedAAuthToken| async move { Json(serde_json::json!({ "ok": true })) }),
        )
        .route_layer(layer);

    let agent_jwt = keys.mint_agent_jwt(issuer, "aauth:test@example.com", None);
    let signing = SigningMaterial {
        signing_jwk: keys.agent_ephemeral.signing_jwk(),
        signature_key: SignatureKey::Jwt(SignatureKeyJwt { jwt: agent_jwt }),
    };

    let authority = "resource.example";
    let path = "/api/data";
    let req = Request::builder()
        .method("GET")
        .uri(path)
        .header(HOST, HeaderValue::from_static(authority))
        .body(Body::empty())
        .unwrap()
        .signed(&signing)
        .unwrap();

    let res = app.oneshot(req).await.unwrap();
    assert_eq!(res.status(), StatusCode::OK);
}
```

For resource-managed mode, also merge `resource_router` and hold a `ResourceServerState` (authorize + pending poll). See `aauth-axum` example `resource_managed`.

### Person Server (axum + policy)

```toml
aauth = { version = "0.0", default-features = false, features = ["person-server"] }
aauth-policy = { version = "0.0", default-features = false, features = ["person-server"] }
aauth-axum = { version = "0.0", default-features = false, features = ["person-server", "policy"] }
```

```rust
#![cfg(all(feature = "person-server", feature = "policy"))]
use aauth::{AbsentAccessServerClient, DEFAULT_PENDING_TTL_SECS, PersonServerConfig, TestKeys};
use aauth_axum::{PersonServerState, person_router};
use aauth_policy::{AlwaysGrantPersonPolicy, InMemoryPersonPendingStore};
use axum::body::Body;
use axum::extract::FromRef;
use axum::http::{Request, StatusCode};
use axum::Router;
use tower::ServiceExt;

type PersonState = PersonServerState<
    aauth_policy::PolicyPersonTokenService<
        AlwaysGrantPersonPolicy,
        InMemoryPersonPendingStore,
        aauth::person_server::keys::TestPersonAuthJwtMinter,
        aauth::StaticMetadataFetcher,
        AbsentAccessServerClient,
    >,
    aauth::StaticMetadataFetcher,
    AbsentAccessServerClient,
>;

#[derive(Clone)]
struct AppState {
    person: PersonState,
}

impl FromRef<AppState> for PersonState {
    fn from_ref(s: &AppState) -> PersonState {
        s.person.clone()
    }
}

#[tokio::main]
async fn main() {
    let keys = TestKeys::generate();
    let person_server_url = "http://ps.example";
    let resource_url = "http://resource.example";

    let person = PersonServerState::from_policy(
        AlwaysGrantPersonPolicy::new("user-123"),
        InMemoryPersonPendingStore::new(),
        keys.person_auth_jwt_minter(),
        PersonServerConfig {
            keys: keys.clone(),
            person_server_url: person_server_url.into(),
            resource_url: resource_url.into(),
            person_jwks_uri: format!("{person_server_url}/auth/jwks"),
            interaction_url: format!("{person_server_url}/interact"),
            pending_base_url: person_server_url.into(),
            pending_path: "/pending".into(),
            pending_ttl_secs: DEFAULT_PENDING_TTL_SECS,
            fetcher: keys.person_metadata_fetcher(person_server_url),
            access_server: AbsentAccessServerClient,
            federation_poll_max_secs: None,
        },
    );

    let app = Router::new()
        .merge(person_router::<AppState, _, _, _>())
        .with_state(AppState { person });

    let res = app
        .oneshot(
            Request::builder()
                .uri("/.well-known/aauth-person.json")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(res.status(), StatusCode::OK);
}
```

### Access Server (axum + policy)

Used when the Person Server federates token exchange (four-party).

```toml
aauth = { version = "0.0", default-features = false, features = ["access-server"] }
aauth-policy = { version = "0.0", default-features = false, features = ["access-server"] }
aauth-axum = { version = "0.0", default-features = false, features = ["access-server", "policy"] }
```

```rust
#![cfg(all(feature = "access-server", feature = "policy"))]
use aauth::{AccessServerConfig, DEFAULT_PENDING_TTL_SECS, TestKeys};
use aauth_axum::{AccessServerState, access_router};
use aauth_policy::{AlwaysGrantAccessPolicy, InMemoryAccessPendingStore};
use axum::body::Body;
use axum::extract::FromRef;
use axum::http::{Request, StatusCode};
use axum::Router;
use tower::ServiceExt;

type AccessState = AccessServerState<
    aauth_policy::PolicyAccessTokenService<
        AlwaysGrantAccessPolicy,
        InMemoryAccessPendingStore,
        aauth::access_server::keys::TestAccessAuthJwtMinter,
        aauth::StaticMetadataFetcher,
    >,
    aauth::StaticMetadataFetcher,
>;

#[derive(Clone)]
struct AppState {
    access: AccessState,
}

impl FromRef<AppState> for AccessState {
    fn from_ref(s: &AppState) -> AccessState {
        s.access.clone()
    }
}

#[tokio::main]
async fn main() {
    let keys = TestKeys::generate();
    let access_server_url = "http://as.example";
    let person_server_url = "http://ps.example";
    let resource_url = "http://resource.example";

    let access = AccessServerState::from_policy(
        AlwaysGrantAccessPolicy::new("user-federated"),
        InMemoryAccessPendingStore::new(),
        keys.access_auth_jwt_minter(),
        AccessServerConfig {
            keys: keys.clone(),
            access_server_url: access_server_url.into(),
            resource_url: resource_url.into(),
            person_server_url: person_server_url.into(),
            access_jwks_uri: format!("{access_server_url}/access/jwks"),
            pending_base_url: access_server_url.into(),
            pending_path: "/access/pending".into(),
            pending_ttl_secs: DEFAULT_PENDING_TTL_SECS,
            fetcher: keys.access_metadata_fetcher(access_server_url),
        },
    );

    let app = Router::new()
        .merge(access_router::<AppState, _, _>())
        .with_state(AppState { access });

    let res = app
        .oneshot(
            Request::builder()
                .uri("/.well-known/aauth-access.json")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(res.status(), StatusCode::OK);
}
```

Server snippets use `aauth-policy` for a quick grant path. Production apps can implement `PersonTokenService` / `AccessTokenService` / `ResourceAccessService` from `aauth` with their own persistence and skip `aauth-policy`.

### Examples

```bash
cargo run -p aauth-axum --example identity_based --all-features
cargo run -p aauth-axum --example person_server_managed --all-features
cargo run -p aauth-axum --example resource_managed --all-features
cargo run -p aauth-axum --example federated --all-features
```

## Development

```bash
cargo test --workspace --all-features
cargo fmt --all
cargo clippy --workspace --all-features -- -D warnings
```

Release notes: [CHANGELOG.md](./CHANGELOG.md). Contributor-oriented architecture notes: [AGENTS.md](./AGENTS.md).

## License

Licensed under either of [Apache License, Version 2.0](LICENSE-APACHE) or [MIT license](LICENSE-MIT) at your option.

Unless you explicitly state otherwise, any contribution intentionally submitted for inclusion in `aauth-rs` shall be dual licensed as above, without additional terms or conditions.
