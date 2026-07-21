# aauth-policy

Opinionated **policy** helpers and pending-store services for AAuth servers.

[`aauth`](https://docs.rs/aauth) defines HTTP-free role traits (`PersonTokenService`, `AccessTokenService`, `ResourceAccessService`). Production code can implement those traits with any persistence and never depend on this crate.

This crate is a shortcut: **stateless policy traits**, a fixed [`PendingStore`] record model, in-memory stores, and [`PolicyPersonTokenService`] / [`PolicyAccessTokenService`] / [`PolicyResourceAccessService`] that implement the `aauth` services.

**Pre-alpha.** Breaking changes are expected.

## Install

```toml
aauth = { version = "0.0", default-features = false, features = ["person-server"] }
aauth-policy = { version = "0.0", default-features = false, features = ["person-server"] }
```

For axum `from_policy` constructors, also enable `aauth-axum` feature `policy`.

## Features

| Feature | Policy trait | Service |
|---------|--------------|---------|
| `person-server` | [`PersonTokenPolicy`] | [`PolicyPersonTokenService`] |
| `access-server` | [`AccessTokenPolicy`] | [`PolicyAccessTokenService`] |
| `resource` | [`ResourceConsentPolicy`] | [`PolicyResourceAccessService`] |
| `full` | all three | all three |

Default features enable all three roles.

## When to use this crate

| Approach | Use when |
|----------|----------|
| Implement `aauth` `*Service` traits yourself | Custom DB schema, complex orchestration, multi-tenant stores |
| Use `aauth-policy` | Prototypes, tests, demos, or apps happy with the built-in pending record shape |

## Policy decisions

Policies are **stateless**. They return grant / deny / defer (and federate for Person Server). In-flight deferred requests are persisted in a [`PendingStore`] inside the `Policy*Service`.

| Trait | Decisions |
|-------|-----------|
| [`PersonTokenPolicy`] | grant auth JWT, deny, defer (interaction / clarification), federate to Access Server |
| [`AccessTokenPolicy`] | grant, deny, defer |
| [`ResourceConsentPolicy`] | grant opaque token, deny, defer |

Decision enums: [`PersonTokenDecision`], [`AccessTokenDecision`], [`ResourceConsentDecision`].

## Pending stores

[`PendingStore`] is the persistence trait. [`InMemoryPendingStore`] (and role-specific aliases such as [`InMemoryPersonPendingStore`]) are suitable for tests and single-process demos. Swap in your own store by implementing [`PendingStore`] / [`PendingStorable`] for the record types you need.

## Reference policies

Ready-made policies for examples and tests (feature-gated per role):

- Person: [`AlwaysGrantPersonPolicy`], [`DeferInteractionPersonPolicy`], [`ClarificationThenGrantPersonPolicy`]
- Access: [`AlwaysGrantAccessPolicy`], [`DeferInteractionAccessPolicy`], [`ClarificationThenGrantAccessPolicy`], …
- Resource: [`AlwaysGrantResourcePolicy`], [`DeferInteractionResourcePolicy`]

## Building a service

```rust
#![cfg(feature = "person-server")]
use aauth::{AbsentAccessServerClient, DEFAULT_PENDING_TTL_SECS, PersonServerConfig, TestKeys};
use aauth_policy::{
    AlwaysGrantPersonPolicy, InMemoryPersonPendingStore, PolicyPersonTokenService,
};

fn main() {
let keys = TestKeys::generate();
let person_server_url = "http://ps.example";
let config = PersonServerConfig {
    keys: keys.clone(),
    person_server_url: person_server_url.into(),
    resource_url: "http://resource.example".into(),
    person_jwks_uri: format!("{person_server_url}/auth/jwks"),
    interaction_url: format!("{person_server_url}/interact"),
    pending_base_url: person_server_url.into(),
    pending_path: "/pending".into(),
    pending_ttl_secs: DEFAULT_PENDING_TTL_SECS,
    fetcher: keys.person_metadata_fetcher(person_server_url),
    access_server: aauth::AbsentAccessServerClient,
    federation_poll_max_secs: None,
};

let service = PolicyPersonTokenService::new(
    AlwaysGrantPersonPolicy::new("user-123"),
    InMemoryPersonPendingStore::new(),
    keys.person_auth_jwt_minter(),
    config,
);
let _ = service;
}
```

Wire that service into HTTP with [`aauth-axum`](https://docs.rs/aauth-axum) (`PersonServerState::from_policy`, `person_router`).

## See also

- Service traits: [`aauth`](https://docs.rs/aauth)
- HTTP adapters: [`aauth-axum`](https://docs.rs/aauth-axum)
- Agent client: [`aauth-reqwest`](https://docs.rs/aauth-reqwest)
