# aauth-rs

Rust implementation of the [AAuth authorization protocol](https://github.com/dickhardt/AAuth).

This workspace provides the `aauth` crate with protocol primitives (always on) and optional modules per AAuth party — enable only the roles you implement.

## ⚠️ WARNING: LLM usage & pre-alpha ⚠️
This library is currently in pre-alpha and can't in any way be described as satisfactory. It's mainly a LLM translation of the `Javascript` implementation of the `aauth` draft and a start for us to work from. We currently discourage using this, and won't be accepting contributions because our internal plans will make any external contributions moot, but if you check back in a few weeks, we're hopefully in a more acceptable state.

## Workspace layout

```text
aauth-rs/
├── Cargo.toml          # workspace root
└── aauth/
    ├── src/
    │   ├── agent/              # agent runtime (feature `agent`)
    │   ├── person_server/      # Person Server (feature `person-server`)
    │   ├── access_server/      # Access Server (feature `access-server`)
    │   ├── resource/           # Resource Server (feature `resource`)
    │   ├── resource_verify/    # token verification only (feature `resource-verify`)
    │   ├── deferred/           # pending store, defer types (feature `deferred`)
    │   ├── policy/             # policy traits (feature `policy`)
    │   ├── server_axum/        # axum IntoResponse + route re-exports (per `*-axum` features)
    │   ├── signature.rs        # shared HTTP Signature build + verify
    │   └── …                   # headers, JWT helpers, metadata, types
    └── tests/                  # protocol integration tests (TypeScript e2e parity)
```

## Protocol roles

| AAuth party | Module |
|-------------|--------|
| Agent | `aauth::agent` |
| Resource server | `aauth::resource` |
| Person server | `aauth::person_server` |
| Access server | `aauth::access_server` |

## Resource access modes

`ResourceAccessMode` on `ResourceAuthLayer` selects how the resource evaluates requests:

| Mode | Variant | Description |
|------|---------|-------------|
| Identity-based | `IdentityBased` | Grant on verified agent or auth token alone |
| PS-asserted (three-party) | `PsAsserted { require_auth_token, access_server_url: None, person_server_fallback }` | Resource token `aud` = agent `ps` claim (or fallback) |
| Federated (four-party) | `PsAsserted { require_auth_token, access_server_url: Some(...), ... }` | Resource token `aud` = AS; PS federates to AS |
| Resource-managed (two-party) | `ResourceManaged { service, ... }` | `ResourceConsentPolicy` + `PendingStore` + opaque `AAuth-Access` tokens |

When the Access Server returns `202` during federation, the Person Server pass-through defers to the agent on its own pending URL, forwards agent input to the AS pending endpoint, and polls until an auth token is ready. Payment (`402`) from the AS remains a stub.

## Policy and deferred store

Server authorization decisions are pluggable via generic policy traits:

| Trait | Role |
|-------|------|
| `PersonTokenPolicy` | PS token exchange: grant, deny, defer, or federate |
| `AccessTokenPolicy` | AS token exchange: grant, deny, or defer |
| `ResourceConsentPolicy` | Resource-managed access: grant opaque, deny, or defer |

Policies are stateless; in-flight deferred requests are persisted in a `PendingStore` implementation (reference: `InMemoryPendingStore`).

Reference policies for tests and examples: `AlwaysGrantPersonPolicy`, `AlwaysGrantAccessPolicy`, `DeferInteractionPersonPolicy`, `ClarificationThenGrantPersonPolicy`, `DeferInteractionResourcePolicy`.

See [CHANGELOG.md](CHANGELOG.md) for version history.

## Naming

Public types use role prefixes: `Agent*` (agent runtime), `Person*` / `Access*` / `Resource*` (server roles), `AAuth*` (protocol wire/errors). Configuration types use builders (`Type::builder(...)`). See [AGENTS.md](AGENTS.md) for full conventions.

The agent JWT `ps` claim names the Person Server when not configured explicitly on the client. Use `agent::resolve::resolve_person_server_url` or omit `person_server_url` on [`AgentOptions`](aauth::agent::injector::AgentOptions) to resolve from the agent token.

## Features

Protocol modules (`error`, `headers`, `jwt`, `signature`, `types`, …) are always available. Enable role features to compile only what you need:

| Feature | Description |
|---------|-------------|
| `agent` | `aauth::agent::injector`, `aauth::agent::keys` |
| `agent-reqwest` | `aauth::agent::reqwest` — `AgentMiddleware`, `ClientBuilder`, token exchange |
| `agent-reqwest-verify` | Optional 401 challenge binding checks (implies `resource-verify`) |
| `person-server` / `person-server-axum` | Person Server service and axum routes |
| `access-server` / `access-server-axum` | Access Server service and axum routes |
| `resource` / `resource-axum` | Resource Server layer, consent service, axum helpers |
| `resource-verify` | Resource token verification only (no RS service/layer) |
| `full` | All roles and integrations (matches `default`) |

**Person Server only:**

```toml
aauth = { version = "0.0", default-features = false, features = ["person-server", "person-server-axum"] }
```

**Agent client only:**

```toml
aauth = { version = "0.0", default-features = false, features = ["agent", "agent-reqwest"] }
```

## Quick example

```rust
use std::sync::Arc;

use aauth::agent::injector::AgentOptions;
use aauth::agent::keys::KeyMaterialProvider;
use aauth::agent::reqwest::{AgentMiddleware, ClientBuilder};
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
        .with(AgentMiddleware::new(
            AgentOptions::builder(Arc::new(MyProvider))
                // person_server_url omitted — resolved from agent JWT `ps` when challenged
                .build(),
        ))
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

- Protocol spec: [draft-hardt-oauth-aauth-protocol.md](./docs/specs/draft-hardt-oauth-aauth-protocol.md)
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

# Per-role minimal builds
cargo check --no-default-features --features person-server,person-server-axum
cargo check --no-default-features --features access-server,access-server-axum
cargo check --no-default-features --features resource,resource-axum
cargo check --no-default-features --features agent,agent-reqwest
```

Release notes: [CHANGELOG.md](CHANGELOG.md).

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
