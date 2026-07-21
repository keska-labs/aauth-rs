# aauth-rs

Rust implementation of the [AAuth authorization protocol](https://github.com/dickhardt/AAuth).

This workspace provides the `aauth` crate with protocol primitives (always on) and optional modules per AAuth party — enable only the roles you implement. Companion crates: `aauth-policy` (high-level policy + pending store), `aauth-reqwest` (agent HTTP client), and `aauth-axum` (server HTTP adapters).

## ⚠️ WARNING: LLM usage & pre-alpha ⚠️
This library is currently in pre-alpha and can't in any way be described as satisfactory. It's mainly a LLM translation of the `Javascript` implementation of the `aauth` draft and a start for us to work from. We currently discourage using this, and won't be accepting contributions because our internal plans will make any external contributions moot, but if you check back in a few weeks, we're hopefully in a more acceptable state.

## Workspace layout

```text
aauth-rs/
├── Cargo.toml              # workspace root
├── aauth/                  # protocol + role service traits
│   ├── src/
│   │   ├── agent/              # agent runtime (feature `agent`)
│   │   ├── person_server/      # Person Server (feature `person-server`)
│   │   ├── access_server/      # Access Server (feature `access-server`)
│   │   ├── resource/           # Resource Server (feature `resource`)
│   │   ├── resource_verify/    # token verification only (feature `resource-verify`)
│   │   ├── deferred/           # defer wire types (feature `deferred`)
│   │   ├── signature.rs        # shared HTTP Signature build + verify
│   │   └── …                   # JWT helpers, metadata, protocol types
│   └── tests/                  # protocol / agent integration tests
├── aauth-policy/           # Policy traits, PendingStore, Policy*Service
├── aauth-reqwest/          # reqwest agent transport (`AgentMiddleware`, signing, exchange)
└── aauth-axum/             # axum HTTP adapters (handlers, ResourceAuthLayer)
    ├── src/
    ├── examples/               # explorer access-mode demos
    └── tests/                  # axum HTTP integration tests
```

## Protocol roles

| AAuth party | Module |
|-------------|--------|
| Agent | `aauth::agent` |
| Resource server | `aauth::resource` |
| Person server | `aauth::person_server` |
| Access server | `aauth::access_server` |

## Resource access modes

`ResourceAccessMode` on `aauth_axum::ResourceAuthLayer` selects how the resource evaluates requests:

| Mode | Variant | Description |
|------|---------|-------------|
| Identity-based | `IdentityBased` | Grant on verified agent or auth token alone |
| PS-asserted (three-party) | `PsAsserted { require_auth_token, access_server_url: None, person_server_fallback }` | Resource token `aud` = agent `ps` claim (or fallback) |
| Federated (four-party) | `PsAsserted { require_auth_token, access_server_url: Some(...), ... }` | Resource token `aud` = AS; PS federates to AS |
| Resource-managed (two-party) | `ResourceManaged { service, ... }` | Custom `ResourceAccessService` (or `aauth-policy` helpers) + opaque `AAuth-Access` tokens |

When the Access Server returns `202` during federation, the Person Server pass-through defers to the agent on its own pending URL, forwards agent input to the AS pending endpoint, and polls until an auth token is ready. Payment (`402`) from the AS remains a stub.

## Integration: services vs `aauth-policy`

**Primary path:** implement `PersonTokenService` / `AccessTokenService` / `ResourceAccessService` from `aauth` with your own persistence.

**Shortcut path:** depend on `aauth-policy` for batteries-included policy traits, `PendingStore`, in-memory stores, and `Policy*Service` implementations. Axum `from_policy` helpers require `aauth-axum` feature `policy`.

| Trait (`aauth-policy`) | Role |
|------------------------|------|
| `PersonTokenPolicy` | PS token exchange: grant, deny, defer, or federate |
| `AccessTokenPolicy` | AS token exchange: grant, deny, or defer |
| `ResourceConsentPolicy` | Resource-managed access: grant opaque, deny, or defer |

Reference policies for tests and examples: `AlwaysGrantPersonPolicy`, `AlwaysGrantAccessPolicy`, `DeferInteractionPersonPolicy`, `ClarificationThenGrantPersonPolicy`, `DeferInteractionResourcePolicy`.

See [CHANGELOG.md](CHANGELOG.md) for version history.

## Naming

Public types use role prefixes: `Agent*` (agent runtime), `Person*` / `Access*` / `Resource*` (server roles), `AAuth*` (protocol wire/errors). Configuration types use builders (`Type::builder(...)`). See [AGENTS.md](AGENTS.md) for full conventions.

The agent JWT `ps` claim names the Person Server when not configured explicitly on the client. Use `agent::resolve::resolve_person_server_url` or omit `person_server_url` on [`AgentOptions`](aauth::agent::auth::AgentOptions) to resolve from the agent token.

## Features

### `aauth`

Protocol modules (`error`, `protocol`, `jwt`, `signature`, …) are always available. Enable role features to compile only what you need:

| Feature | Description |
|---------|-------------|
| `agent` | `aauth::agent` — `AgentAuth`, `AgentOptions`, keys, resolve |
| `person-server` | Person Server service trait |
| `access-server` | Access Server service trait |
| `resource` | Resource Server consent service trait |
| `resource-verify` | Resource token verification only (no RS service/layer) |
| `full` | All roles and agent (matches `default`) |

### `aauth-policy`

| Feature | Description |
|---------|-------------|
| `person-server` | `PersonTokenPolicy` + `PolicyPersonTokenService` |
| `access-server` | `AccessTokenPolicy` + `PolicyAccessTokenService` |
| `resource` | `ResourceConsentPolicy` + `PolicyResourceAccessService` |
| `full` | All three (matches `default`) |

### `aauth-reqwest`

| Feature | Description |
|---------|-------------|
| `verify` (default) | 401 challenge / auth-token binding checks via `aauth/resource-verify` |

### `aauth-axum`

| Feature | Description |
|---------|-------------|
| `person-server` | Person Server axum routes (`PersonServerState`, handlers) |
| `access-server` | Access Server axum routes |
| `resource` | `ResourceAuthLayer`, pending poll, `VerifiedAAuthToken` |
| `policy` | `from_policy` helpers via `aauth-policy` |
| `full` | Roles + `policy` |

**Person Server with axum + policy shortcut:**

```toml
aauth = { version = "0.0", default-features = false, features = ["person-server"] }
aauth-policy = { version = "0.0", default-features = false, features = ["person-server"] }
aauth-axum = { version = "0.0", default-features = false, features = ["person-server", "policy"] }
```

**Agent client only:**

```toml
aauth = { version = "0.0", default-features = false, features = ["agent"] }
aauth-reqwest = { version = "0.0" }
```

## Quick example

```rust
use std::sync::Arc;

use aauth::agent::auth::AgentOptions;
use aauth::agent::keys::KeyMaterialProvider;
use aauth::protocol::KeyMaterial;
use aauth_reqwest::{AgentMiddleware, ClientBuilder};

#[async_trait::async_trait]
impl KeyMaterialProvider for MyProvider {
    async fn key_material(&self) -> aauth::Result<KeyMaterial> {
        // Return ephemeral signing JWK + agent/auth JWT for Signature-Key
        todo!()
    }
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
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
        .await?;

    println!("status: {}", response.status());
    Ok(())
}
```

Key material is injected via `KeyMaterialProvider` (equivalent to the TypeScript `@aauth/local-keys` package, which is not included here). For development and tests, use the public [`aauth::keys`](aauth::keys) module — it provides Ed25519 key generation, JWT minting, and static metadata/key providers.

## Examples

Each example mirrors an access mode from the [AAuth explorer](https://explorer.aauth.dev/):

```bash
# Identity Based — agent JWT alone grants access
cargo run -p aauth-axum --example identity_based

# Person Server Managed — 401 challenge, token exchange at the Person Server
cargo run -p aauth-axum --example person_server_managed

# Resource Managed — resource-owned interaction and opaque AAuth-Access tokens
cargo run -p aauth-axum --example resource_managed

# Federated — Person Server delegates token exchange to an Access Server
cargo run -p aauth-axum --example federated
```

Each example has a matching E2E test in `aauth-axum/tests/example_flows.rs` (run with `cargo test -p aauth-axum --test example_flows --all-features`).

Build all examples in CI:

```bash
cargo build -p aauth-axum --examples --all-features
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
cargo test --workspace --all-features
cargo fmt --all
cargo clippy --workspace --all-features -- -D warnings

# aauth without axum
cargo check -p aauth --no-default-features --features person-server
cargo check -p aauth --no-default-features --features access-server
cargo check -p aauth --no-default-features --features resource
cargo check -p aauth --no-default-features --features agent
cargo check -p aauth-reqwest --all-features
cargo check -p aauth-policy --all-features

# aauth-axum adapters
cargo check -p aauth-axum --no-default-features --features person-server
cargo check -p aauth-axum --no-default-features --features access-server
cargo check -p aauth-axum --no-default-features --features resource
cargo check -p aauth-axum --all-features
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
