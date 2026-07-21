# aauth-axum

Axum HTTP adapters for AAuth **Person**, **Access**, and **Resource** servers.

Domain types and service traits live in [`aauth`](https://docs.rs/aauth). This crate maps them to HTTP: role routers, extractors, [`ResourceAuthLayer`], and [`AauthResponse`] (`IntoResponse` wrappers for orphan-rule compliance).

**Pre-alpha.** Breaking changes are expected.

## Install

```toml
# Resource server only
aauth-axum = { version = "0.0", default-features = false, features = ["resource"] }

# Person Server + aauth-policy shortcut
aauth = { version = "0.0", default-features = false, features = ["person-server"] }
aauth-policy = { version = "0.0", default-features = false, features = ["person-server"] }
aauth-axum = { version = "0.0", default-features = false, features = ["person-server", "policy"] }
```

## Features

| Feature | What you get |
|---------|----------------|
| `person-server` | [`PersonServerState`], [`person_router`], token / pending / interaction handlers |
| `access-server` | [`AccessServerState`], [`access_router`], token / pending handlers |
| `resource` | [`ResourceAuthLayer`], [`resource_router`], [`VerifiedAAuthToken`], pending poll |
| `policy` | `from_policy` constructors via [`aauth-policy`](https://docs.rs/aauth-policy) |
| `full` | All of the above (+ `aauth-reqwest` for workspace README doctests) |

Default features enable the three role features (not `policy`).

## Resource protection

Apply [`ResourceAuthLayer`] to protected routes. After the layer succeeds, handlers extract [`VerifiedAAuthToken`]:

```rust
#![cfg(feature = "resource")]
use std::sync::Arc;

use aauth::protocol::{KeyMaterial, SignatureKey, SignatureKeyJwt};
use aauth::signature::sign_request_headers;
use aauth::{NoResourceAccessService, ResourceAccessMode, TestKeys};
use aauth_axum::{ResourceAuthLayer, VerifiedAAuthToken};
use axum::body::Body;
use axum::http::{Request, StatusCode, header::HOST};
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
let material = KeyMaterial {
    signing_jwk: keys.agent_ephemeral.signing_jwk(),
    signature_key: SignatureKey::Jwt(SignatureKeyJwt { jwt: agent_jwt }),
};

let authority = "resource.example";
let path = "/api/data";
let mut headers = axum::http::HeaderMap::new();
headers.insert(HOST, authority.parse().unwrap());
sign_request_headers(&mut headers, "GET", authority, path, &material, None).unwrap();

let mut req = Request::builder()
    .method("GET")
    .uri(path)
    .body(Body::empty())
    .unwrap();
*req.headers_mut() = headers;

let res = app.oneshot(req).await.unwrap();
assert_eq!(res.status(), StatusCode::OK);
}
```

### Access modes

| Mode | [`ResourceAccessMode`](https://docs.rs/aauth/latest/aauth/resource/enum.ResourceAccessMode.html) | Notes |
|------|--------------------------------------------------------------------------------------------------|-------|
| Identity-based | `IdentityBased` | Agent JWT alone |
| Person Server managed | `PsAsserted { access_server_url: None, … }` | Challenge → PS token exchange |
| Federated | `PsAsserted { access_server_url: Some(…), … }` | PS federates to Access Server |
| Resource-managed | `ResourceManaged { service, … }` | Opaque `AAuth-Access` via [`ResourceAccessService`](https://docs.rs/aauth/latest/aauth/resource/trait.ResourceAccessService.html) |

## Role routers

Prefer merging canonical routers over wiring handlers by hand:

- [`person_router`] — `POST /token`, pending GET/POST, JWKS, metadata, interaction
- [`access_router`] — Access Server token + pending + JWKS + metadata
- [`resource_router`] — resource pending poll + `POST /resource/authorize` (resource-managed)

App state must implement [`FromRef`](https://docs.rs/axum/latest/axum/extract/trait.FromRef.html) to the matching `*ServerState`.

### Person Server

```rust
#![cfg(all(feature = "person-server", feature = "policy"))]
use aauth::{DEFAULT_PENDING_TTL_SECS, PersonServerConfig, TestKeys};
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
    >,
    aauth::StaticMetadataFetcher,
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
        http_client: reqwest::Client::new(),
        federation_poll_max_secs: None,
    },
);

let app = Router::new()
    .merge(person_router::<AppState, _, _>())
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

### Access Server

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

Implement [`PersonTokenService`](https://docs.rs/aauth/latest/aauth/person_server/trait.PersonTokenService.html) or [`AccessTokenService`](https://docs.rs/aauth/latest/aauth/access_server/trait.AccessTokenService.html) (or the resource counterpart) directly if you do not want `aauth-policy`.

## Responses and errors

Service outcomes map through [`AauthResponse`]: `200` / `202` / `403` / `410` / `502` as appropriate. Unexpected service `Err` becomes `500` + `{ "error": "server_error" }` via [`InternalServiceError`]. Pending resume bodies use [`PendingResumeInput`] (`FromRequest`).

Domain types stay HTTP-free in `aauth`; only this crate implements `IntoResponse` / `FromRequest`.

## Examples

Each example mirrors an [explorer](https://explorer.aauth.dev/) access mode:

```bash
cargo run -p aauth-axum --example identity_based --all-features
cargo run -p aauth-axum --example person_server_managed --all-features
cargo run -p aauth-axum --example resource_managed --all-features
cargo run -p aauth-axum --example federated --all-features
```

Matching HTTP tests: `cargo test -p aauth-axum --test person_managed --all-features` (and siblings).

## See also

- Core protocol: [`aauth`](https://docs.rs/aauth)
- Agent client: [`aauth-reqwest`](https://docs.rs/aauth-reqwest)
- Policy shortcut: [`aauth-policy`](https://docs.rs/aauth-policy)
