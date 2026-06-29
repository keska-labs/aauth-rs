# Changelog

All notable changes to this project are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [0.0.2] - 2026-06-29

Changes since [0.0.1].

### Changed

- Renamed `AAuthClientOptions` to `AgentOptions` with an `AgentOptions::builder(provider)` API; optional fields are set via builder methods instead of struct literals.
- Renamed agent-side types: `AAuthMiddleware` → `AgentMiddleware`, `AAuthInjector` → `AgentAuth`, `AuthAttempt` → `AgentAuthAttempt`, `InjectorStep` → `AgentAuthStep`, `DeferredOptions` → `AgentDeferredOptions` (with builder).
- Renamed resource server axum types: `AAuthLayer` → `ResourceAuthLayer`, `AAuthService` → `ResourceAuthService`.
- `TokenExchangeOptions` now uses a builder API (`TokenExchangeOptions::builder(person_server_url, resource_token)`).

### Added

- Pluggable server policy traits (`PersonTokenPolicy`, `AccessTokenPolicy`, `ResourceConsentPolicy`) and `PendingStore` / `InMemoryPendingStore` for deferred flows (`DeferRequirement`, `PendingInput`, `PendingOutcome`).
- Generic Person/Access axum state (`PersonServerState<P, S, M>`, `AccessServerState<P, S, M>`) and `ResourceAccessMode<P, S, O>`.
- Shared deferred helpers: `build_accepted`, `map_snapshot_to_poll_parts`, pending poll/post route handlers.
- **Federation deferred loop**: when the Access Server returns `202` during PS→AS token exchange, the Person Server pass-through defers to the agent on its own pending URL, forwards agent input to the AS pending endpoint, and polls until an auth token is ready (`FederationOutcome`, `FederationPendingState`, `parse_deferred_response`, `post_pending_input`, `poll_pending_http`).
- Access Server pending routes and reference policies: `ClarificationThenGrantAccessPolicy`, `DeferInteractionAccessPolicy`, `DeferClaimsAccessPolicy`, `DeferApprovalAccessPolicy`.
- `federated` example and matching E2E tests (`example_flows`, `axum_integration`).
- `max_poll_duration_secs` on `AgentOptions` / `TokenExchangeOptions` (default 300s).
- `federation_poll_max_secs` on `PersonServerConfig` for server-side federation pending polls.
- Integration tests: `federated_as_clarification_deferred_over_http`, `federated_as_interaction_deferred_over_http`.
- Wiremock unit tests for `post_pending_input` and `poll_pending_http`.
- `rstest` `#[timeout]` on HTTP integration tests for fast failure.

### Removed

- `AAuthClientOptions` (use `AgentOptions` and `AgentOptions::builder`).
- `AAuthMiddleware`, `AAuthInjector`, `AuthAttempt`, `InjectorStep`, `DeferredOptions`, `AAuthLayer`, `AAuthService` (see renamed replacements above).
- `InteractionManager`, `InteractionManagerOptions`, `PendingRequest`.
- Test-only server flags: `deferred_mode`, `clarification_prompt`, `pending_id_capture`.

### Fixed

- `post_pending_input` sends `{}` for interaction/cancel completions so axum accepts the POST body.
- `post_pending_input` parses a `200` response body directly as an auth token, avoiding an extra poll when the pending POST completes immediately.

## [0.0.1] - 2026-06-28

Initial pre-alpha release.

[0.0.2]: https://github.com/keska-labs/aauth-rs/compare/v0.0.1...v0.0.2
[0.0.1]: https://github.com/keska-labs/aauth-rs/releases/tag/v0.0.1
