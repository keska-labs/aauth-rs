# aauth-rs

Rust implementation of the [AAuth authorization protocol](https://github.com/dickhardt/AAuth).

This workspace provides the `aauth` crate with protocol primitives, a **client** module for signed requests and token exchange, and a **server** module for token verification, pluggable policy traits, and a deferred pending store.

## ⚠️ WARNING: LLM usage & pre-alpha ⚠️
This library is currently in pre-alpha and can't in any way be described as satisfactory. It's mainly a LLM translation of the `Javascript` implementation of the `aauth` draft and a start for us to work from. We currently discourage using this, and won't be accepting contributions because our internal plans will make any external contributions moot, but if you check back in a few weeks, we're hopefully in a more acceptable state.

## Workspace layout

```text
aauth-rs/
├── Cargo.toml          # workspace root
└── aauth/
    ├── src/
    │   ├── client/
    │   │   ├── injector.rs   # framework-agnostic auth flow
    │   │   ├── keys.rs       # KeyMaterialProvider, JWT minting
    │   │   ├── resolve.rs    # PS URL resolution from agent `ps` claim
    │   │   └── reqwest/      # AAuthMiddleware, token exchange (feature "client-reqwest")
    │   ├── server/
    │   │   ├── deferred/     # PendingStore, deferred response builders
    │   │   ├── policy/       # PersonTokenPolicy, AccessTokenPolicy, ResourceConsentPolicy
    │   │   ├── resource/     # verify, resource tokens, ResourceAccessMode, AAuthLayer
    │   │   ├── person/       # federation, auth JWT minting, PS route helpers
    │   │   ├── access/       # AS auth JWT minting and route helpers
    │   │   └── axum/         # facade re-exporting resource + person + access axum helpers
    │   ├── signature.rs      # shared HTTP Signature build + verify
    │   └── …                 # headers, JWT helpers, metadata cache
    └── tests/                # protocol integration tests (TypeScript e2e parity)
```

## Protocol roles

| AAuth party | Module |
|-------------|--------|
| Agent | `aauth::client` |
| Resource server | `aauth::server::resource` |
| Person server | `aauth::server::person` |
| Access server | `aauth::server::access` |

## Resource access modes

`ResourceAccessMode` on `AAuthLayer` selects how the resource evaluates requests:

| Mode | Variant | Description |
|------|---------|-------------|
| Identity-based | `IdentityBased` | Grant on verified agent or auth token alone |
| PS-asserted (three-party) | `PsAsserted { require_auth_token, access_server_url: None, person_server_fallback }` | Resource token `aud` = agent `ps` claim (or fallback) |
| Federated (four-party) | `PsAsserted { require_auth_token, access_server_url: Some(...), ... }` | Resource token `aud` = AS; PS federates to AS |

When the Access Server returns `202` during federation, the Person Server pass-through defers to the agent on its own pending URL, forwards agent input to the AS pending endpoint, and polls until an auth token is ready. Payment (`402`) from the AS remains a stub.
| Resource-managed (two-party) | `ResourceManaged { policy, pending, opaque, ... }` | `ResourceConsentPolicy` + `PendingStore` + opaque `AAuth-Access` tokens |

## Policy and deferred store

Server authorization decisions are pluggable via generic policy traits (monomorphized on axum state, not `Arc<dyn>`):

| Trait | Role |
|-------|------|
| `PersonTokenPolicy` | PS token exchange: grant, deny, defer, or federate |
| `AccessTokenPolicy` | AS token exchange: grant, deny, or defer |
| `ResourceConsentPolicy` | Resource-managed access: grant opaque, deny, or defer |

Policies are stateless; in-flight deferred requests are persisted in a `PendingStore` implementation (reference: `InMemoryPendingStore`). Deferred responses use shared builders (`build_accepted`, `map_snapshot_to_poll_parts`).

Reference policies for tests and examples: `AlwaysGrantPersonPolicy`, `AlwaysGrantAccessPolicy`, `DeferInteractionPersonPolicy`, `ClarificationThenGrantPersonPolicy`, `DeferInteractionResourcePolicy`.

### Breaking changes (0.0.1)

- Removed: `InteractionManager`, `InteractionManagerOptions`, `PendingRequest`
- Added: `PendingStore`, `InMemoryPendingStore`, policy traits, `DeferRequirement`, `PendingInput`, `PendingOutcome`
- `ResourceAccessPolicy` is now a type alias for a concrete `ResourceAccessMode` with default policies; use `ResourceAccessMode<P, S, O>` for custom policy/store types
- Person/Access axum state is generic over `P: *Policy`, `S: PendingStore`, `M: *JwtMinter`

The agent JWT `ps` claim names the Person Server when not configured explicitly on the client. Use `client::resolve::resolve_person_server_url` or leave `person_server_url` unset on `AAuthClientOptions` to resolve from the agent token.

## Features

| Feature | Default | Description |
|---------|---------|-------------|
| `client` | yes | `aauth::client::injector`, `aauth::client::keys` — auth flow and key material |
| `client-reqwest` | yes | `aauth::client::reqwest` — `AAuthMiddleware`, `ClientBuilder`, `exchange_token`, `poll_deferred` |
| `server` | yes | `verify_token`, `verify_resource_token`, `create_resource_token`, `PendingStore`, policy traits |
| `server-axum` | yes | `aauth::server::axum` — `AAuthLayer`, `ResourceAccessPolicy`, route helpers |

Disable defaults to depend on only one side:

```toml
aauth = { version = "0.1", default-features = false, features = ["client-reqwest"] }
```

## Quick example

```rust
use std::sync::Arc;

use aauth::client::injector::AAuthClientOptions;
use aauth::client::keys::KeyMaterialProvider;
use aauth::client::reqwest::{AAuthMiddleware, ClientBuilder};
use aauth::types::KeyMaterial;

#[async_trait::async_trait]
impl KeyMaterialProvider for MyProvider {
    async fn key_material(&self) -> aauth::Result<KeyMaterial> {
        // Return ephemeral signing JWK + agent/auth JWT for Signature-Key
        todo!()
    }
}

#[tokio::main]
async fn main() -> aauth::Result<()> {
    let client = ClientBuilder::new(reqwest::Client::new())
        .with(AAuthMiddleware::new(AAuthClientOptions {
            provider: Arc::new(MyProvider),
            person_server_url: None, // resolved from agent JWT `ps` claim when challenged
            person_server_metadata: None,
            on_metadata: None,
            on_auth_token: None,
            on_opaque_token: None,
            opaque_token: None,
            on_interaction: None,
            on_clarification: None,
            justification: None,
            login_hint: None,
            tenant: None,
            domain_hint: None,
            capabilities: None,
            mission: None,
            prompt: None,
        }))
        .build();

    let response = client
        .get("https://resource.example/api")
        .send()
        .await
        .map_err(|e| aauth::AAuthError::Message(e.to_string()))?;

    println!("status: {}", response.status());
    Ok(())
}
```

Key material is injected via `KeyMaterialProvider` (equivalent to the TypeScript `@aauth/local-keys` package, which is not included here). For development and tests, use the public [`aauth::keys`](aauth::keys) module — it provides Ed25519 key generation, JWT minting, and static metadata/key providers.

## Examples

Each example mirrors an access mode from the [AAuth explorer](https://explorer.aauth.dev/):

```bash
# Identity Based — agent JWT alone grants access
cargo run --example identity_based

# Person Server Managed — 401 challenge, token exchange at the Person Server
cargo run --example person_server_managed

# Resource Managed — resource-owned interaction and opaque AAuth-Access tokens
cargo run --example resource_managed

# Federated — Person Server delegates token exchange to an Access Server
cargo run --example federated
```

Each example has a matching E2E test in `tests/example_flows.rs` (run with `cargo test --test example_flows --all-features`).

Build all examples in CI:

```bash
cargo build --examples --all-features
```

## Spec and reference

- Protocol spec: [draft-hardt-oauth-aauth-protocol.md](https://raw.githubusercontent.com/dickhardt/AAuth/refs/heads/main/draft-hardt-oauth-aauth-protocol.md)
- Reference implementation: [`aauth-dev/packages-js`](https://github.com/aauth-dev/packages-js)

## Out of scope (initial release)

- `aauth-local-keys` crate (OS keychain, hardware keys, bootstrap CLI)
- MCP bridges and CLI tools
- Claims exchange (`requirement=claims`)

## Development

```bash
cargo test --all-features
cargo fmt --all
cargo clippy --all-features -- -D warnings
```

## License

<sup>
Licensed under either of <a href="LICENSE-APACHE">Apache License, Version
2.0</a> or <a href="LICENSE-MIT">MIT license</a> at your option.
</sup>

<br>

<sub>
Unless you explicitly state otherwise, any contribution intentionally submitted
for inclusion in `aauth-rs` by you, as defined in the Apache-2.0 license, shall be
dual licensed as above, without any additional terms or conditions.
</sub>
