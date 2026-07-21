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
├── aauth/                  # protocol + role service traits (no axum / reqwest agent)
│   ├── src/
│   │   ├── agent/              # agent runtime (feature `agent`)
│   │   ├── person_server/      # Person Server (feature `person-server`)
│   │   ├── access_server/      # Access Server (feature `access-server`)
│   │   ├── resource/           # Resource Server (feature `resource`)
│   │   ├── resource_verify/    # token verification only (feature `resource-verify`)
│   │   ├── deferred/           # DeferCreated/DeferWaiting, PendingInput (feature `deferred`)
│   │   ├── signature.rs        # shared HTTP Signature build + verify
│   │   └── …                   # JWT helpers, metadata cache, protocol types
│   └── tests/                  # protocol / agent integration tests
├── aauth-policy/           # high-level Policy* + PendingStore + Policy*Service
├── aauth-reqwest/          # reqwest agent transport + `ReqwestAccessServerClient` (PS federation)
└── aauth-axum/             # axum HTTP adapters
    ├── src/
    │   ├── person/             # Person Server handlers, person_router, PersonServerState
    │   ├── access/             # Access Server handlers, access_router, AccessServerState
    │   ├── resource/           # ResourceAuthLayer, resource_router, VerifiedAAuthToken
    │   ├── extract.rs          # PendingResumeInput
    │   └── respond.rs          # AauthResponse, InternalServiceError, polling_status
    ├── examples/               # explorer access-mode demos
    └── tests/                  # axum HTTP integration tests
```

**Shared protocol primitives** (no role prefix, always on): `protocol`, `jwt`, `metadata`, `interaction_code`. HTTP Signature Keys live in workspace crate `httpsig-key`. These implement wire format and are used by all roles.

**Cargo features (`aauth`):** per-role `person-server`, `access-server`, `resource`; agent `agent`; meta `server`, `full`. Protocol modules need no feature flag.

**Cargo features (`aauth-policy`):** `person-server`, `access-server`, `resource`, `full` — each enables the matching `aauth` role feature.

**Cargo features (`aauth-reqwest`):** optional `person-server` enables `ReqwestAccessServerClient`. Resource-challenge verification always runs; auth-token claim checks always run. Auth JWT signature verification defaults on (`AgentOptions::verify_auth_signature`); set a `MetadataFetcher` for JWKS discovery.

**Cargo features (`aauth-axum`):** `person-server`, `access-server`, `resource`; optional `policy` enables `from_policy` helpers via `aauth-policy`. Prefer `person_router` / `access_router` / `resource_router` (`merge` or `nest`) over hand-wiring individual handlers; apply `ResourceAuthLayer` to protected app routes separately.

### Agent request flow

The agent side is split into a transport-agnostic state machine and a reqwest adapter:

1. **`AgentAuth`** (`agent/auth.rs`) — tracks per-origin cached auth/opaque tokens; on each response decides the next step (`AgentAuthStep`: continue, finish, exchange token, poll deferred, invalidate attempt).
2. **`AgentMiddleware`** (`aauth-reqwest`) — reqwest middleware that drives `AgentAuth`, signs requests via `SigningMiddleware`, calls `exchange_token` and `poll_deferred` when needed.
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

`aauth_axum::ResourceAuthLayer` selects how the resource server evaluates requests (`ResourceAccessMode`):

| Mode | Variant | Parties | Description |
|------|---------|---------|-------------|
| Identity-based | `IdentityBased` | 2 | Grant on verified agent JWT alone; missing credential → `requirement=agent-token` |
| PS-asserted | `PsAsserted { access_server_url: None, ... }` | 3 | Resource token `aud` = agent `ps` claim; PS mints auth token |
| Federated | `PsAsserted { access_server_url: Some(...), ... }` | 4 | Resource token `aud` = AS; PS federates token exchange to AS |
| Resource-managed | `ResourceManaged { service, ... }` | 2 | Resource owns consent via `ResourceAccessService` (e.g. `aauth_policy::PolicyResourceAccessService`); issues opaque `AAuth-Access` tokens |

When the Access Server returns `202` during federation, the Person Server pass-through defers to the agent on its own pending URL, forwards agent input to the AS pending endpoint, and polls until an auth token is ready (`aauth-policy` federation pending + `aauth` `deferred/poll.rs`). Payment (`402`) from the AS remains a stub.

### Server services and `aauth-policy`

The **primary integration surface** is the role service traits in `aauth`. Axum handlers verify signatures/JWTs then call the service and map outcomes via `AauthResponse` / `IntoResponse`:

| Trait | Role | Methods |
|-------|------|---------|
| `PersonTokenService` | PS token exchange / pending | `exchange_token`, `poll_pending`, `resume_pending` |
| `AccessServerClient` | PS→AS federation (outbound) | `fetch_metadata`, `exchange_token`, `resume_pending`, `poll_pending` |
| `AccessTokenService` | AS token exchange / pending | `exchange_token`, `poll_pending`, `resume_pending` |
| `ResourceAccessService` | RS resource-managed consent | `consent_for_agent`, `poll_pending`, `validate_opaque` |

Implement these traits with your own persistence for production. The companion crate **`aauth-policy`** is intentionally higher-level: it provides stateless policy traits, a fixed `PendingStore` record model, in-memory stores, and `Policy*Service` implementations of the traits above.

| Policy trait (`aauth-policy`) | Role | Decisions |
|-------------------------------|------|-----------|
| `PersonTokenPolicy` | PS token exchange | grant, deny, defer, federate |
| `AccessTokenPolicy` | AS token exchange | grant, deny, defer |
| `ResourceConsentPolicy` | Resource-managed access | grant opaque, deny, defer |

Policies are **stateless**. In-flight deferred requests are persisted in a `PendingStore` (`InMemoryPendingStore` for tests) inside `aauth-policy`.

Service `Err` maps to spec `500` + `{ "error": "server_error" }` via `InternalServiceError`; protocol outcomes (`AuthTokenFlowOutcome`, etc.) map to 200/202/403/410/502 in `aauth-axum` via `AauthResponse`.

**Defer semantics (HTTP-free, in `aauth`):** `DeferCreated` (initial 202 + `Location`), `DeferWaiting` (poll 202), `PendingBody` (serialize-side JSON). Flow outcomes carry these types; axum converts them via `AauthResponse` / `IntoResponse` in `aauth-axum` only.

**Pending POST ingress:** `PendingPostBody` (`#[serde(untagged)]` until the spec adds a wire discriminator) → `parse_pending_post_body` / `PendingResumeInput` `FromRequest` on person/access pending handlers.

See [`.cursor/rules/prefer-rust-traits.mdc`](.cursor/rules/prefer-rust-traits.mdc): domain types stay HTTP-free; use `AauthResponse` / `IntoResponse` / `FromRequest` in `aauth-axum`, not `*_to_response` mappers.

Axum state types hold a single service field: `PersonServerState<S>`, `AccessServerState<S>`, `ResourceServerState<S>` (in `aauth-axum`). With feature `policy`, use `PersonServerState::from_policy(...)` for the `aauth-policy` setup.

Reference test policies (in `aauth-policy`): `AlwaysGrantPersonPolicy`, `AlwaysGrantAccessPolicy`, `DeferInteractionPersonPolicy`, `ClarificationThenGrantPersonPolicy`, `DeferInteractionResourcePolicy`, `ClarificationThenGrantAccessPolicy`.

Examples in `aauth-axum/examples/` mirror the [AAuth explorer](https://explorer.aauth.dev/) access modes and show full axum wiring (`ResourceAuthLayer`, routers, `VerifiedAAuthToken`). Matching HTTP tests live under `aauth-axum/tests/` (`identity_based`, `person_managed`, `resource_managed`, `federated`) with one-hop app definers in `tests/support/apps/`. Hybrid `@aauth/fetch` CLI interop tests are `fetch_person_server` and `fetch_federated_hosted_ps` (ignored by default).

## Naming conventions

Public types follow a **role prefix** that matches AAuth protocol parties:

| Prefix | Role | Examples |
|--------|------|----------|
| `Agent*` | Agent runtime (signed requests, token exchange, deferred polling) | `AgentOptions`, `AgentMiddleware`, `AgentAuth`, `AgentDeferredOptions` |
| `Person*` / `Access*` | Person Server and Access Server | `PersonServerConfig`, `PersonTokenService` (`PersonServerState` in `aauth-axum`; `PersonTokenPolicy` in `aauth-policy`) |
| `Resource*` | Resource Server | `ResourceAccessMode`, `ResourceAccessService` (`ResourceConsentPolicy` in `aauth-policy`; `ResourceAuthLayer` in `aauth-axum`) |
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
cargo test --workspace --all-features
cargo fmt --all
cargo clippy --workspace --all-features -- -D warnings

cargo check -p aauth --no-default-features --features person-server
cargo check -p aauth --no-default-features --features access-server
cargo check -p aauth --no-default-features --features resource
cargo check -p aauth --no-default-features --features agent
cargo check -p aauth-reqwest --all-features
cargo check -p aauth-policy --all-features
cargo check -p aauth-axum --all-features
```

### Fetch CLI interop (hybrid local + hosted)

Ignored by default. Needs Node/`npx`, `@aauth/bootstrap` config (`AAUTH_DIR` or `~/.aauth`), and a tunnel whose public URL is in `AAUTH_E2E_PUBLIC_BASE` (local servers advertise that base via `AAUTH_E2E_BIND` / `AAUTH_E2E_PUBLIC_BASE` so hosted parties can reach local JWKS).

```bash
# Local Person Server + https://whoami.aauth.dev
AAUTH_E2E_PUBLIC_BASE=https://your-tunnel.example \
  cargo test -p aauth-axum --test fetch_person_server --features full -- --ignored --nocapture

# Local resource + hosted Person Server (person.hello.coop; three-party — hosted PS
# expects resource-token aud = PS, not a local Access Server)
AAUTH_E2E_PUBLIC_BASE=https://your-tunnel.example \
  cargo test -p aauth-axum --test fetch_federated_hosted_ps --features full -- --ignored --nocapture
```

Optional env: `AAUTH_E2E_WHOAMI`, `AAUTH_E2E_PERSON_SERVER`, `AAUTH_E2E_BIND` (fixed bind for tunnels, e.g. `127.0.0.1:18765`).
