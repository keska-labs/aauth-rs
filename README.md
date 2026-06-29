# aauth-rs

Rust implementation of the [AAuth authorization protocol](https://github.com/dickhardt/AAuth).

This workspace provides the `aauth` crate with protocol primitives, a **client** module for signed requests and token exchange, and a **server** module for token verification and interaction management.

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
    │   │   └── reqwest/      # AAuthMiddleware, token exchange (feature "client-reqwest")
    │   ├── server/
    │   │   ├── resource/     # verify, resource tokens, AAuthLayer (feature "server-axum")
    │   │   ├── person/       # interaction, auth JWT minting, PS route helpers
    │   │   ├── access/       # stub for four-party federation
    │   │   └── axum/         # facade re-exporting resource + person axum helpers
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
| Access server | `aauth::server::access` (stub) |

## Features

| Feature | Default | Description |
|---------|---------|-------------|
| `client` | yes | `aauth::client::injector`, `aauth::client::keys` — auth flow and key material |
| `client-reqwest` | yes | `aauth::client::reqwest` — `AAuthMiddleware`, `ClientBuilder`, `exchange_token`, `poll_deferred` |
| `server` | yes | `verify_token`, `create_resource_token`, `InteractionManager` |
| `server-axum` | yes | `aauth::server::axum` — `AAuthLayer`, `VerifiedAAuthToken`, person-server route helpers |

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
            person_server_url: Some("https://person.example".into()),
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

```bash
# Direct agent grant: axum resource server + reqwest client
cargo run --example direct_agent_grant

# Full 401 auth-token challenge with token exchange
cargo run --example auth_token_challenge
```

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
- AS federation / four-party `claims` exchange

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
