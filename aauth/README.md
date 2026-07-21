# aauth

Core Rust library for the [AAuth authorization protocol](https://github.com/dickhardt/AAuth).

This crate provides protocol wire types, JWT and HTTP-signature helpers, metadata fetchers, and **role service traits** for agents, Person Servers, Access Servers, and resource servers. It has **no** axum or reqwest transport — use companion crates for those.

| Need | Crate |
|------|-------|
| Agent HTTP client | [`aauth-reqwest`](https://docs.rs/aauth-reqwest) |
| PS→AS federation HTTP | [`aauth-reqwest`](https://docs.rs/aauth-reqwest) (`ReqwestAccessServerClient`, feature `person-server`) |
| Axum handlers / `ResourceAuthLayer` | [`aauth-axum`](https://docs.rs/aauth-axum) |
| Policy + in-memory pending stores | [`aauth-policy`](https://docs.rs/aauth-policy) |

**Pre-alpha:** APIs break freely. Prefer matching the [protocol draft](https://github.com/keska-labs/aauth-rs/blob/main/docs/specs/draft-hardt-oauth-aauth-protocol.md) over copying incidental local patterns.

## Install

```toml
# Protocol types only (always available)
aauth = { version = "0.0", default-features = false }

# Agent state machine + challenge verification
aauth = { version = "0.0", default-features = false, features = ["agent"] }

# Person Server service trait
aauth = { version = "0.0", default-features = false, features = ["person-server"] }
```

## Features

Protocol modules (`protocol`, `jwt`, `metadata`, `error`, …) are **always** compiled. Role features gate the rest:

| Feature | What you get |
|---------|----------------|
| `agent` | [`agent`] — `AgentAuth`, `AgentOptions`, key providers (includes `resource-verify`) |
| `person-server` | [`person_server`] — `PersonTokenService`, config, federation helpers |
| `access-server` | [`access_server`] — `AccessTokenService`, config |
| `resource` | [`resource`] — `ResourceAccessService`, `ResourceAccessMode`, token signing |
| `resource-verify` | [`resource_verify`] — challenge / auth-token verification only |
| `deferred` | [`deferred`] — `DeferCreated`, pending poll types (pulled in by server roles) |
| `server` | `person-server` + `access-server` + `resource` |
| `full` | All roles and agent |

Default features enable `agent`, `person-server`, `access-server`, and `resource`.

## Protocol roles

| Party | Module | You implement / use |
|-------|--------|---------------------|
| Agent | [`agent`] | [`KeyMaterialProvider`], drive [`agent::auth::AgentAuth`] via a transport adapter |
| Resource | [`resource`] | [`ResourceAccessService`] (resource-managed) or choose a [`ResourceAccessMode`] |
| Person Server | [`person_server`] | [`PersonTokenService`] — grant, deny, defer, or federate |
| Access Server | [`access_server`] | [`AccessTokenService`] — grant, deny, or defer |

Primary integration surface for servers: implement the `*Service` traits with your own persistence. [`aauth-policy`](https://docs.rs/aauth-policy) is an optional shortcut that supplies policy traits and `Policy*Service` implementations.

## Always-on modules

- [`protocol`] — headers, challenges, token exchange bodies, metadata documents, governance wire types
- [`jwt`] — agent / auth / resource claim types and parsing
- [`metadata`] — `MetadataFetcher` and simple static/local fetchers
- [`keys`] — Ed25519 helpers and [`TestKeys`] for examples and tests
- [`error`] — `AAuthError` and typed domain errors (includes `SignatureError`; `SignatureErrorHeader` re-exported from `httpsig_key`)

## Agent overview

[`agent::auth::AgentAuth`] is a transport-agnostic state machine over status codes and headers. Pair it with [`aauth-reqwest::AgentMiddleware`](https://docs.rs/aauth-reqwest/latest/aauth_reqwest/struct.AgentMiddleware.html) for a full client.

```rust
#![cfg(feature = "agent")]
use aauth::TestKeys;
use aauth::agent::auth::AgentOptions;

fn main() {
let keys = TestKeys::generate();
let issuer = "https://example.com";
let agent_jwt = keys.mint_agent_jwt(issuer, "aauth:test@example.com", None);

let options = AgentOptions::builder(keys.key_provider(agent_jwt))
    .metadata_fetcher(keys.agent_metadata_fetcher(issuer))
    // person_server_url omitted → resolved from agent JWT `ps` when challenged
    .build();
let _ = options;
}
```

Omit `person_server_url` to resolve the Person Server from the agent token’s `ps` claim via [`resolve_person_server_url`].

## Resource access modes

[`ResourceAccessMode`] selects how a resource evaluates requests (enforced in axum by [`ResourceAuthLayer`](https://docs.rs/aauth-axum/latest/aauth_axum/struct.ResourceAuthLayer.html)):

| Mode | Variant | Parties |
|------|---------|---------|
| Identity-based | `IdentityBased` | 2 — grant on verified agent JWT |
| PS-asserted | `PsAsserted { access_server_url: None, … }` | 3 — resource token `aud` = agent `ps` |
| Federated | `PsAsserted { access_server_url: Some(…), … }` | 4 — resource token `aud` = Access Server |
| Resource-managed | `ResourceManaged { service, … }` | 2 — resource-owned consent + opaque `AAuth-Access` |

## Naming

Public types use role prefixes: `Agent*`, `Person*` / `Access*` / `Resource*`, and `AAuth*` for protocol-wide wire/errors. Configuration uses builders (`Type::builder(…)` → setters → `.build()`).

## Spec

- Draft: [draft-hardt-oauth-aauth-protocol.md](https://github.com/keska-labs/aauth-rs/blob/main/docs/specs/draft-hardt-oauth-aauth-protocol.md)
- Explorer: [explorer.aauth.dev](https://explorer.aauth.dev/access/compare)
- Reference JS: [aauth-dev/packages-js](https://github.com/aauth-dev/packages-js)
