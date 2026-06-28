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
    │   ├── client/     # signed fetch, token exchange, protocol-aware fetch
    │   ├── server/     # verify_token, resource tokens, InteractionManager
    │   └── …           # shared headers, JWT helpers, metadata cache
    └── tests/          # protocol integration tests (TypeScript e2e parity)
```

## Features

| Feature | Default | Description |
|---------|---------|-------------|
| `client` | yes | `create_signed_fetch`, `create_aauth_fetch`, `exchange_token`, `poll_deferred` |
| `server` | yes | `verify_token`, `create_resource_token`, `InteractionManager` |

Disable defaults to depend on only one side:

```toml 
aauth = { version = "0.1", default-features = false, features = ["client"] }
```

## Quick example

```rust
use std::sync::Arc;

use aauth::client::{create_aauth_fetch, AAuthFetchOptions, HttpClientAdapter, KeyMaterialProvider};
use aauth::http::{HttpRequest, ReqwestClient};
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
    let client = Arc::new(ReqwestClient::new()) as Arc<dyn HttpClientAdapter>;
    let fetch = create_aauth_fetch(AAuthFetchOptions {
        provider: Arc::new(MyProvider),
        client,
        auth_server_url: Some("https://person.example".into()),
        auth_server_metadata: None,
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
    });

    let response = fetch
        .fetch(
            "https://resource.example/api",
            HttpRequest {
                method: "GET".into(),
                url: "https://resource.example/api".into(),
                headers: Default::default(),
                body: None,
            },
        )
        .await?;

    println!("status: {}", response.status);
    Ok(())
}
```

Key material is injected via `KeyMaterialProvider` (equivalent to the TypeScript `@aauth/local-keys` package, which is not included here). For development and tests, use the public [`aauth::keys`](aauth::keys) module — it provides Ed25519 key generation, JWT minting, and static metadata/key providers.

## Examples

```bash
# Verify an agent JWT (server only)
cargo run --example verify_agent_token --features server

# Signed fetch against an in-process mock resource (client + server)
cargo run --example client_direct_grant
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
- Production HTTP signature verification middleware for axum/actix

## Development

```bash
cargo test --all-features
cargo fmt --all
cargo clippy --all-features -- -D warnings
```

## License

MIT
