# Agent guidelines

Notes for humans and coding agents working in this repository.

## Architecture

This crate is a **Rust implementation of the AAuth authorization draft** — not a separate protocol definition. Behavior should match the spec and the reference TypeScript implementation, not incidental patterns in local code.

### Protocol reference

When implementing or changing protocol behavior — headers, signatures, token exchange, interactions, metadata, error semantics, or any other AAuth surface — use the canonical spec as the source of truth:

**[draft-hardt-oauth-aauth-protocol.md](./docs/specs/draft-hardt-oauth-aauth-protocol.md)**

For mode comparisons, flow diagrams, and explanatory copy, use the **[AAuth Protocol Explorer](https://explorer.aauth.dev/access/compare)**. Its UI text is authored in native TSX in **[aauth-dev/explorer](https://github.com/aauth-dev/explorer)** — read the relevant page/components there when you need the source behind the explorer content, not just the rendered site.

**How to use the spec:**

- Read the relevant section in the draft before guessing behavior from local code alone.
- Use the explorer for high-level mode/flow context; use the explorer repo TSX when you need exact wording or page structure.
- Prefer matching the spec over matching incidental patterns in this repo if they diverge.
- If the spec and existing code disagree, treat the spec as authoritative unless the user says otherwise.

The reference JS implementation lives in [`aauth-dev/packages-js`](https://github.com/aauth-dev/packages-js). Integration tests in `aauth/tests/` aim for parity with its e2e flows.

### Protocol parties

AAuth has four roles. Each maps to a module in this crate:

| AAuth party | Crate module | Responsibility |
|-------------|--------------|----------------|
| **Agent** | `aauth::agent` | Signs requests, handles 401 challenges, exchanges resource tokens for auth tokens, polls deferred responses |
| **Resource server** | `aauth::resource` | Verifies agent/auth JWTs and HTTP signatures; issues resource tokens; enforces access mode |
| **Person server** | `aauth::person_server` | Token exchange endpoint; may defer, federate to an Access Server, or mint auth JWTs |
| **Access server** | `aauth::access_server` | Token exchange when the Person Server delegates authorization (federated / four-party mode) |

The agent JWT's `ps` claim names the Person Server. When `person_server_url` is omitted on `AgentOptions`, the client resolves it from the agent token via `agent::resolve::resolve_person_server_url`.

### Crate layout

```text
aauth-rs/
├── Cargo.toml              # workspace root
└── aauth/
    ├── src/
    │   ├── agent/              # agent runtime (feature `agent`)
    │   ├── person_server/      # Person Server (feature `person-server`)
    │   ├── access_server/      # Access Server (feature `access-server`)
    │   ├── resource/           # Resource Server (feature `resource`)
    │   ├── resource_verify/    # token verification only (feature `resource-verify`)
    │   ├── deferred/           # PendingStore, DeferCreated/DeferWaiting (feature `deferred`)
    │   ├── policy/             # PersonTokenPolicy, AccessTokenPolicy, ResourceConsentPolicy
    │   ├── server_axum/        # IntoResponse, PendingResumeInput, route re-exports (per `*-axum`)
    │   ├── signature.rs        # shared HTTP Signature build + verify
    │   └── …                   # headers, JWT helpers, metadata cache, types
    └── tests/                  # protocol integration tests (TypeScript e2e parity)
```

**Shared protocol primitives** (no role prefix, always on): `headers`, `signature`, `jwt`, `metadata`, `types`, `interaction_code`. These implement wire format and are used by all roles.

**Cargo features:** per-role `person-server`, `access-server`, `resource`, `person-server-axum`, `access-server-axum`, `resource-axum`; agent `agent`, `agent-reqwest`, `agent-reqwest-verify`; meta `server`, `full`. Protocol modules need no feature flag. Disable defaults to compile only the roles you need.

### Agent request flow

The agent side is split into a transport-agnostic state machine and a reqwest adapter:

1. **`AgentAuth`** (`agent/injector.rs`) — tracks per-origin cached auth/opaque tokens; on each response decides the next step (`AgentAuthStep`: continue, finish, exchange token, poll deferred, invalidate attempt).
2. **`AgentMiddleware`** (`agent/reqwest/middleware/agent.rs`) — reqwest middleware that drives `AgentAuth`, signs requests via `SigningMiddleware`, calls `exchange_token` and `poll_deferred` when needed.
3. **`AgentOptions`** — configuration builder (provider, PS URL, callbacks, poll limits).

Typical three-party flow:

```text
Agent ──signed request──▶ Resource
Agent ◀──401 + AAuth-Requirement (resource_token)── Resource
Agent ──POST /token (resource_token)──▶ Person Server
Agent ◀──200 (auth_token) or 202 (defer)── Person Server
Agent ──signed request + auth token──▶ Resource
Agent ◀──200── Resource
```

Deferred responses (`202 Accepted` + `Location` + optional `AAuth-Requirement`) are polled by `poll_deferred` / `AgentDeferredOptions`. Interaction and clarification callbacks fire from `AgentOptions`.

### Resource access modes

`ResourceAuthLayer` selects how the resource server evaluates requests (`ResourceAccessMode`):

| Mode | Variant | Parties | Description |
|------|---------|---------|-------------|
| Identity-based | `IdentityBased` | 2 | Grant on verified agent or auth token alone |
| PS-asserted | `PsAsserted { access_server_url: None, ... }` | 3 | Resource token `aud` = agent `ps` claim; PS mints auth token |
| Federated | `PsAsserted { access_server_url: Some(...), ... }` | 4 | Resource token `aud` = AS; PS federates token exchange to AS |
| Resource-managed | `ResourceManaged { service, ... }` | 2 | Resource owns consent via `ResourceAccessService` (default: `PolicyResourceAccessService`); issues opaque `AAuth-Access` tokens |

When the Access Server returns `202` during federation, the Person Server pass-through defers to the agent on its own pending URL, forwards agent input to the AS pending endpoint, and polls until an auth token is ready (`person_server/federation.rs`, `deferred/poll.rs`). Payment (`402`) from the AS remains a stub.

### Server policy, services, and deferred store

Authorization decisions are pluggable via generic policy traits. Flow orchestration (policy evaluation, pending store, token minting) lives in **role service traits**; axum handlers verify signatures/JWTs then call the service and map outcomes via `IntoResponse`:

| Trait | Role | Methods |
|-------|------|---------|
| `PersonTokenService` | PS token exchange / pending | `exchange_token`, `poll_pending`, `resume_pending` |
| `AccessTokenService` | AS token exchange / pending | `exchange_token`, `poll_pending`, `resume_pending` |
| `ResourceAccessService` | RS resource-managed consent | `consent_for_agent`, `poll_pending`, `validate_opaque` |

Default implementations (`PolicyPersonTokenService`, `PolicyAccessTokenService`, `PolicyResourceAccessService`) wrap the policy traits below plus `PendingStore` and JWT minters. Service `Err` maps to spec `500` + `{ "error": "server_error" }` via `InternalServiceError`; protocol outcomes (`AuthTokenFlowOutcome`, etc.) map to 200/202/403/410/502 in `server_axum/respond.rs`.

| Policy trait | Role | Decisions |
|--------------|------|-----------|
| `PersonTokenPolicy` | PS token exchange | grant, deny, defer, federate |
| `AccessTokenPolicy` | AS token exchange | grant, deny, defer |
| `ResourceConsentPolicy` | Resource-managed access | grant opaque, deny, defer |

Policies are **stateless**. In-flight deferred requests are persisted in a `PendingStore` (`InMemoryPendingStore` for tests).

**Defer semantics (HTTP-free):** `DeferCreated` (initial 202 + `Location`), `DeferWaiting` (poll 202), `PendingBody` (serialize-side JSON). Flow outcomes carry these types; axum converts them via `IntoResponse` in `server_axum/respond.rs` only.

**Pending POST ingress:** `PendingPostBody` (`#[serde(untagged)]` until the spec adds a wire discriminator) → `parse_pending_post_body` / `PendingResumeInput` `FromRequest` on person/access pending handlers.

See [`.cursor/rules/prefer-rust-traits.mdc`](.cursor/rules/prefer-rust-traits.mdc): domain types stay HTTP-free; use `IntoResponse` / `FromRequest`, not `*_to_response` mappers.

Axum state types hold a single service field: `PersonServerState<S>`, `AccessServerState<S>`, `ResourceServerState<S>`. Use `PersonServerState::from_policy(...)` for the default policy-backed setup.

Reference test policies: `AlwaysGrantPersonPolicy`, `AlwaysGrantAccessPolicy`, `DeferInteractionPersonPolicy`, `ClarificationThenGrantPersonPolicy`, `DeferInteractionResourcePolicy`, `ClarificationThenGrantAccessPolicy`.

Examples in `aauth/examples/` mirror the [AAuth explorer](https://explorer.aauth.dev/) access modes; matching E2E tests live in `tests/example_flows.rs`.

## Naming conventions

Public types follow a **role prefix** that matches AAuth protocol parties:

| Prefix | Role | Examples |
|--------|------|----------|
| `Agent*` | Agent runtime (signed requests, token exchange, deferred polling) | `AgentOptions`, `AgentMiddleware`, `AgentAuth`, `AgentDeferredOptions` |
| `Person*` / `Access*` | Person Server and Access Server | `PersonServerState`, `PersonTokenService`, `AccessTokenPolicy` |
| `Resource*` | Resource Server | `ResourceAuthLayer`, `ResourceAccessMode`, `ResourceConsentPolicy` |
| `AAuth*` | Protocol-wide wire format, headers, and errors | `AAuthError`, `AAuthRequirementParams` |

**Do not** use `Client*` for first-party agent types — `agent` is the module path.

Configuration types use a **builder** (`Type::builder(...)` → chained setters → `.build()`), not public struct literals with many optional fields.

Internal state-machine types (`AgentAuthAttempt`, `AgentAuthStep`) are exported for custom transport adapters but are not typically constructed by application code.

## Pre-alpha

See [`.cursor/rules/prealpha-breaking-changes.mdc`](.cursor/rules/prealpha-breaking-changes.mdc): rename in place, update all call sites, no compatibility shims.

## Changelog

User-visible API changes belong in [CHANGELOG.md](CHANGELOG.md) under the unreleased or current version (see [`.cursor/rules/changelog.mdc`](.cursor/rules/changelog.mdc)).

## Development

```bash
cargo test --all-features
cargo fmt --all
cargo clippy --all-features -- -D warnings

cargo check --no-default-features --features person-server,person-server-axum
cargo check --no-default-features --features access-server,access-server-axum
cargo check --no-default-features --features resource,resource-axum
cargo check --no-default-features --features agent,agent-reqwest
```
