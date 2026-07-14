# Changelog

All notable changes to this project are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [0.0.3]

### Added

- `aauth::protocol` module — single source of truth for cross-party wire types (JWT claim payloads, metadata documents, headers, token exchange, authorization, pending/governance bodies, protocol errors). Types remain re-exported at the crate root.
- Spec-complete governance wire types: `MissionProposalRequest`, `PermissionRequest`/`PermissionResponse`, `InteractionRequest`, `AuditRequest`, and related payloads.
- `AuthorizationRequest`, `ResourceTokenResponse`, `AuthorizationGrantedResponse`, and resource authorization response bodies in `protocol::authorization`.
- `AgentProviderMetadata` (replaces loose `MetadataDocument`) with typed agent-provider metadata fields from the spec.
- `PaymentRequiredBody` in `protocol::pending` for `402` deferred poll responses.
- Resource-initiated interaction: `ResourceInteractionProvider` and `interaction` on `ResourceTokenOptions`; PS `begin_interaction` / `resolve_interaction_callback` with `GET /interact` and `GET /interact/callback` axum handlers.
- Public `sign_request`, `sign_request_with_auth_token`, and related helpers on `aauth::agent::reqwest` for custom transport adapters.

### Changed

- JWT claim payload structs (`AgentClaims`, `AuthClaims`, `ResourceClaims`, …) moved from `jwt::claims` to `protocol::jwt`; `jwt` retains decode/verify only.
- `AAuthChallenge` and header build/parse helpers moved from `headers` to `protocol::headers`.
- Pending wire bodies (`PendingBody`, `PendingPostBody`, `PendingStatusBody`, clarification/claims challenges) moved from `deferred`/`types` to `protocol::pending`; `deferred` keeps server-state types only.
- Crate-root re-exports now source protocol types from `protocol` instead of removed `types` and `headers` modules.

### Changed

- JWT claim payload structs (`AgentClaims`, `AuthClaims`, `ResourceClaims`, …) moved from `jwt::claims` to `protocol::jwt`; `jwt` retains decode/verify only.
- `AAuthChallenge` and header build/parse helpers moved from `headers` to `protocol::headers`.
- Pending wire bodies (`PendingBody`, `PendingPostBody`, `PendingStatusBody`, clarification/claims challenges) moved from `deferred`/`types` to `protocol::pending`; `deferred` keeps server-state types only.
- Crate-root re-exports now source protocol types from `protocol` instead of removed `types` and `headers` modules.
- Restructured `src/` into protocol-party modules: `agent`, `person_server`, `access_server`, `resource`, with shared siblings `deferred`, `policy`, and `server_axum`.
- Granular Cargo features per role: `person-server`, `access-server`, `resource`, `person-server-axum`, `access-server-axum`, `resource-axum`; meta-features `server` and `full`.
- Renamed features `client` → `agent`, `client-reqwest` → `agent-reqwest`; optional `agent-reqwest-verify` for 401 challenge binding checks via `resource-verify`.
- `AuthTokenFlowOutcome` / `AuthTokenPollOutcome` moved to `deferred` (shared by Person and Access servers).
- `ResourceAccessMode` lives in `resource::mode` (was `resource::policy`).
- Flat crate-root re-exports are feature-gated to match enabled roles.

### Removed

- `aauth::types` and `aauth::headers` modules (use `aauth::protocol` or flat crate-root re-exports).
- `MetadataDocument` (use `AgentProviderMetadata`).
- `TokenExchangeOptions::localhost_callback` (not a spec token-exchange field).
- `aauth::client` module path (use `aauth::agent`).
- `aauth::server` umbrella module (use role modules or flat re-exports).
- `server` as a single module gate; use per-role features instead.

### Added

- `resource-verify` feature — resource token verification (`verify_resource_token`, `verify_token`, audience resolution) without the full Resource Server service or axum layer.
- `resource_verify` module for token verification used by Person Server federation and optional agent middleware.
- `PersonServerOutboundSigner` and `OutboundSignatureProvider` trait for federation pending POST signing.
- `full` meta-feature matching previous default feature set.

## [0.0.2] - 2026-06-29

Changes since [0.0.1].

### Changed

- Renamed `AAuthClientOptions` to `AgentOptions` with an `AgentOptions::builder(provider)` API; optional fields are set via builder methods instead of struct literals.
- Renamed agent-side types: `AAuthMiddleware` → `AgentMiddleware`, `AAuthInjector` → `AgentAuth`, `AuthAttempt` → `AgentAuthAttempt`, `InjectorStep` → `AgentAuthStep`, `DeferredOptions` → `AgentDeferredOptions` (with builder).
- Renamed resource server axum types: `AAuthLayer` → `ResourceAuthLayer`, `AAuthService` → `ResourceAuthService`.
- `TokenExchangeOptions` now uses a builder API (`TokenExchangeOptions::builder(person_server_url, resource_token)`).
- `AAuthChallenge` is now an enum keyed by requirement level; each variant carries only the parameters defined for that level (`AuthToken { resource_token }`, `Interaction { url, code }`, etc.).
- `build_aauth_requirement` takes `&AAuthChallenge` instead of `(RequirementLevel, Option<AAuthRequirementParams>)`.
- `PendingStore<R>` is generic over role-specific pending records (`PersonPendingRecord`, `AccessPendingRecord`, `ResourcePendingRecord`); `InMemoryPendingStore<R>` and per-role store aliases replace the unified record enum.
- `PendingStatus` moved to `aauth::types` (wire `status` on pending response bodies).
- `TokenExchangeRequest.capabilities` is `Option<Vec<Capability>>` instead of `Option<Vec<String>>`.
- `ClarificationChallenge.status` and `ClaimsChallenge.status` use `PendingStatus` instead of `String` / `Option<String>`.
- `PersonServerState<S>`, `AccessServerState<S>`, and `ResourceServerState<S>` hold a single role service (`PersonTokenService`, `AccessTokenService`, `ResourceAccessService`) instead of separate policy, pending store, and minter fields; use `PersonServerState::from_policy` / `AccessServerState::from_policy` or construct `Policy*TokenService` directly.
- `ResourceAccessMode::ResourceManaged` holds a `ResourceAccessService` instead of inline `policy`, `pending`, and `opaque` fields.
- Token and pending endpoint internal failures return `500` with JSON `{ "error": "server_error" }` per spec (via `InternalServiceError`), replacing bare empty `500` responses.
- Flow outcome types live under each role module (`server/access/outcome`, `server/person/outcome`, `server/resource/outcome`) instead of `server/service`.
- Flow outcomes carry `DeferCreated` / `DeferWaiting` instead of `AcceptedResponse`; HTTP assembly is axum `IntoResponse` only (`server/axum/respond.rs`).
- `AAuthProtocolError::polling_status()` moved to `server::axum::polling_status` (no axum on protocol types).

### Added

- Spec-linked doc comments on protocol payload types with per-field documentation from the AAuth draft.
- `ResourceInteractionClaim` and optional `interaction` claim on `ResourceClaims`.
- Spec-aligned optional fields: `parent_agent` on `AgentClaims`, nested `act` on `ActClaim`, `upstream_token` / `subagent_token` / `platform` / `device` on `TokenExchangeRequest`, `timeout` / `options` on `ClarificationChallenge`. (`PersonTokenPolicy`, `AccessTokenPolicy`, `ResourceConsentPolicy`) and `PendingStore` / `InMemoryPendingStore` for deferred flows (`DeferRequirement`, `PendingInput`, `PendingOutcome`).
- Role service traits and default policy-backed implementations: `PersonTokenService` / `PolicyPersonTokenService`, `AccessTokenService` / `PolicyAccessTokenService`, `ResourceAccessService` / `PolicyResourceAccessService`.
- Flow outcome types with axum `IntoResponse`: `AuthTokenFlowOutcome`, `AuthTokenPollOutcome`, `PersonTokenFlowOutcome`, `ResourceConsentFlowOutcome`, `ResourcePollOutcome`.
- `AAuthErrorCode` enum for spec token/polling/signature/interaction error codes, with `Custom(String)` for extensions.
- `InternalServiceError` and `AAuthProtocolError::server_error()` for spec-shaped infrastructure failures on token/pending endpoints.
- Semantic defer types: `DeferCreated`, `DeferWaiting`, `PaymentRequiredDefer`, `PendingBody`, `PendingPostBody`, `parse_pending_post_body`.
- `PendingResumeInput` axum extractor for typed pending POST bodies (`#[serde(untagged)]` until spec adds a wire discriminator).
- Pending poll/post route handlers; `parse_deferred_response` uses header-driven typed body deserialize.
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
- `AAuthRequirementParams` (use `AAuthChallenge` variants directly).
- `PendingContext` and `PendingKind` (each server store is typed to its own pending record).
- `InteractionManager`, `InteractionManagerOptions`, `PendingRequest`.
- Test-only server flags: `deferred_mode`, `clarification_prompt`, `pending_id_capture`.
- `AcceptedResponse`, `PollResponse`, `build_accepted`, `build_payment_required_stub`, `map_snapshot_to_poll_parts`, `deferred_accepted`, `parse_pending_input`.

### Fixed

- `post_pending_input` sends `{}` for interaction/cancel completions so axum accepts the POST body.
- `post_pending_input` parses a `200` response body directly as an auth token, avoiding an extra poll when the pending POST completes immediately.
- Resource-managed `202` defer responses include spec JSON body via `IntoResponse` (was empty body).

## [0.0.1] - 2026-06-28

Initial pre-alpha release.

[0.0.2]: https://github.com/keska-labs/aauth-rs/compare/v0.0.1...v0.0.2
[0.0.1]: https://github.com/keska-labs/aauth-rs/releases/tag/v0.0.1
