# Changelog

All notable changes to this project are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [0.0.3]

### Added

- Workspace crate `httpsig-key`: HTTP Signature Keys (`Signature-Key` / `Signature-Error` / Accept-Signature `sigkey`) on top of `httpsig` 0.0.24 (`jwt` + `hwk` schemes; Ed25519 + P-256 sign/verify).
- `sign_request_headers` in `aauth::signature` for signing a `HeaderMap` with `KeyMaterial`.
- Canonical protocol header name constants in `protocol::headers` (`AAUTH_REQUIREMENT` / `_NAME`, `AAUTH_ACCESS`, `AAUTH_CAPABILITIES`, `AAUTH_MISSION`, `SIGNATURE_KEY`, `SIGNATURE_INPUT`, `SIGNATURE`, `PREFER`).
- `StaticKeyMaterialProvider::new` to wrap arbitrary `KeyMaterial` (e.g. from `@aauth/bootstrap token`).
- `IntoAauthProtocol` to map domain errors to HTTP status + `AAuthProtocolError`.
- Typed domain errors under `AAuthError`: `JwtError`, `MetadataError`, `VerifyError`, `DeferredError`, `HeaderError`, `AgentAuthError`, `ResourceTokenError` (catch-all `Message` / stringly `TokenError` removed).
- `AgentError` in `aauth-reqwest` for typed agent transport failures (`Auth`, `Exchange`, `Deferred`, `Signature`, `Jwt`, `Metadata`, `Aauth`, `BodyNotCloneable`).
- `SignatureError` for HTTP Message Signature build/parse/verify failures (defined with the error umbrella, re-exported as `aauth::signature::SignatureError`).
- `PersonOrchestrationError` for person-server policy orchestration failures (interaction URL validation, missing resource interaction claim, pending body build).
- Workspace crate `aauth-policy`: high-level `PersonTokenPolicy` / `AccessTokenPolicy` / `ResourceConsentPolicy`, `PendingStore` + in-memory stores, and `Policy*Service` implementations of the `aauth` role service traits.
- `NoResourceAccessService` marker for `ResourceAccessMode` variants that do not use a consent service.
- Optional `aauth-axum` feature `policy` for `PersonServerState::from_policy` / `AccessServerState::from_policy` via `aauth-policy`.
- Workspace crate `aauth-reqwest`: reqwest agent transport (`AgentMiddleware`, `sign_request`, token exchange, deferred poll, `CachedMetadataFetcher`). Default feature `verify` enables challenge/auth-token binding checks via `aauth/resource-verify`.
- Public getters on `AgentOptions` for transport adapters (`provider`, callbacks, hints, `metadata_fetcher` when `resource-verify` is on).
- `person_router`, `access_router`, and `resource_router` in `aauth-axum` to mount canonical role routes (`merge` / `nest` into an app whose state implements `FromRef` to the matching `*ServerState`).
- Workspace crate `aauth-axum`: axum handlers, extractors, `ResourceAuthLayer`, `*ServerState`, and `AauthResponse<T>` (`IntoResponse` wrappers for domain outcomes).
- `@aauth/fetch` CLI interop tests (`fetch_person_server`, `fetch_federated_hosted_ps`) for hybrid local axum + hosted whoami / Person Server (ignored; need bootstrap + `AAUTH_E2E_PUBLIC_BASE`).
- Spec-complete governance wire types: `MissionProposalRequest`, `PermissionRequest`/`PermissionResponse`, `InteractionRequest`, `AuditRequest`, and related payloads.
- `AuthorizationRequest`, `ResourceTokenResponse`, `AuthorizationGrantedResponse`, and resource authorization response bodies in `protocol::authorization`.
- `AgentProviderMetadata` (replaces loose `MetadataDocument`) with typed agent-provider metadata fields from the spec.
- `PaymentRequiredBody` in `protocol::pending` for `402` deferred poll responses.
- Resource-initiated interaction: `ResourceInteractionProvider` and `interaction` on `ResourceTokenOptions`; PS `begin_interaction` / `resolve_interaction_callback` with `GET /interact` and `GET /interact/callback` axum handlers (now in `aauth-axum`).
- `PersonServerConfig` and `AccessServerConfig` as domain config types (no longer gated on axum).
- `poll_outcome_from_snapshot` in `aauth` deferred module.
- `NoResourceInteraction` marker for `ResourceAuthLayer` when no resource-initiated interaction claim is needed.
- Blanket `MetadataFetcher` / `ResourceTokenSigner` / `ResourceInteractionProvider` impls for `Arc<T>`, so shared deps can be owned concretely or wrapped for cheap `Clone`.
- `Local*` / `Dyn*` companions for crate-owned async traits (`KeyMaterialProvider`, `MetadataFetcher`, role services, policy traits, `PendingStore`, …).

### Fixed

- HTTP Message Signature `@method` component uses uppercase (RFC 9421); lowercase broke verification against `@hellocoop/httpsig` / whoami.aauth.dev.
- Person and Access token-exchange handlers verify HTTP signatures against the request path (`OriginalUri`) instead of hardcoded paths, so Access Server routes remain nestable.

### Changed

- Async traits use `trait_variant` + `dynosaur`: each crate-owned async trait has a `Local*` base (`Sync`), a Send variant keeping the previous public name, and a public `Dyn*` type (except `PendingStore`, which is generic over `R` and uses in-place `trait_variant::make(Send)` only). `Arc<dyn Trait>` call sites use `Arc<DynTrait<'static>>` (construct with `DynTrait::new_arc`).
- `PendingStore::find_if` takes `impl Fn(&R) -> bool + Send` instead of a generic type parameter.
- `Clone` is no longer a supertrait of role/policy service traits (needed for `Dyn*` object-safety); call sites that clone keep an explicit `+ Clone` bound.
- Blanket `MetadataFetcher` / `ResourceTokenSigner` `Arc<T>` (and `MetadataFetcher` for `&T`) impls remain for concrete shared ownership.

### Removed

- Direct `async-trait` dependency from `aauth` / `aauth-policy` / `aauth-axum` production deps (retained as `aauth` / `aauth-reqwest` **dev**/runtime deps only for foreign `reqwest_middleware::Middleware` impls).

### Changed (prior)

- `ResourceAuthLayer` / `ResourceAuthService` take type parameters for `MetadataFetcher`, `ResourceTokenSigner`, and `ResourceInteractionProvider` instead of `Arc<dyn …>` (default interaction provider is `NoResourceInteraction`).
- `PersonServerConfig` / `AccessServerConfig`, `VerifyTokenOptions` / `VerifyResourceTokenOptions`, and related verify helpers are generic over `MetadataFetcher`; `PersonServerState` / `AccessServerState` and `Policy*TokenService` carry the same fetcher type parameter.
- `person_router` / `access_router` take a fetcher type parameter so they match generic `*ServerState`.
- `ResourceTokenOptions::sign` takes `&impl ResourceTokenSigner`; `post_pending_input` takes `Option<&S>` for `OutboundSignatureProvider`.

- Reuse `httpsig-key` JWK types: `OkpJwk` / `OkpSigningJwk` → `PublicJwk` / `SigningJwk` (re-exported); `jwk_thumbprint` delegates to `httpsig-key`; `jwk_set_from_okp` → `jwk_set_from_public`.
- Rename `VerifiedToken` → `ParsedToken` (now includes `Resource`); `decode_unverified` / `decode_verified` → `parse` / `verify_with_key`; remove `decode_resource_token_unverified`.
- Rename `OkpSigningKey` → `SigningKey`; `TestKeys` party key `kid`s default to JWK thumbprint.
- `PersonAuthJwtMinter` / `AccessAuthJwtMinter` take `agent_jwk: &PublicJwk` and return `Result`; `PersonServerConfig::mint_person_auth` takes `&AgentClaims` so auth JWT `cnf` matches the real agent key.
- JWT verification picks `Validation` algorithms from the token header (`EdDSA` or `ES256`); jsonwebtoken 10 rejects mixed algorithm families. Enables Secure Enclave / `@aauth/bootstrap` agent tokens.
- `aauth-axum` examples build real axum apps in-file (`identity_resource_app`, `person_server_app`, … returning a `Router` served from `main`) with separate listeners per party; identity-based uses `ResourceAccessMode::IdentityBased`. Tests use one-hop app definers under `tests/support/apps/` instead of `TestScenario` / `spawn_test_server`.
- `aauth` HTTP Message Signature sign/verify uses workspace crate `httpsig-key` (RFC 9421 via `httpsig`).
- `aauth-reqwest` signing: `RequestSigningExt` on `reqwest::Request` (`.sign` / `.sign_with_auth_token`), `SigningOptions::apply_to`; removed free `sign_request` / `SignRequest` on `KeyMaterial` / free `sign_and_run` shim.
- Demoted signature parse helpers (`parse_signature_*`) and removed thin `build_signature_base`; shared `http_util` for URL normalize + reqwest→http header copy; folded `person_server_from_agent_jwt` into `resolve_person_server_url`; demoted `resolve_deferred_location`.
- `aauth-policy` defer/decision/federation helpers are private methods on `Policy*Service`; `AccessPendingContext` converts via `From` into `AccessTokenContext`.
- Role constructors are methods: `AccessTokenContext::from_exchange`, `PersonServerConfig::verify_token_request` / `mint_person_auth` / `federate_to_access_server`, `ResourceTokenOptions::sign` (free `build_access_context`, `verify_person_token_request`, `create_resource_token`, and free `federate_to_access_server` / `mint_person_auth` removed).
- Header codecs are methods: `AAuthChallenge::to_header` / `from_header`, `Mission::to_header` / `from_header`, `Capability::join_header` / `parse_header` (free `build_*` / `parse_*` header helpers removed).
- Remodeled `AAuthError` as a transparent umbrella over domain errors (`JwtError`, `SignatureError`, `MetadataError`, `VerifyError`, `DeferredError`, `HeaderError`, `AgentAuthError`, `ResourceTokenError`); removed catch-all `Message` / stringly `HttpError` / `TokenError`.
- `ResourceTokenSigner` / `create_resource_token` return `ResourceTokenError` instead of `String`; metadata `validate()` returns `MetadataError`.
- `aauth-reqwest` public APIs (`exchange_token`, `poll_deferred`, `sign_request`, …) return `Result<T, AgentError>` instead of `aauth::Result`; token exchange failures propagate `TokenExchangeError` without stringifying.
- Signature helpers (`verify_request_signature`, `apply_outbound_signature`, parsers) return `Result<T, SignatureError>` instead of `AAuthError`.
- `PersonTokenServiceError`, `AccessTokenServiceError`, and `ResourceAccessServiceError` are generic over the pending-store error type (`*ServiceError<E>`); store failures keep their typed source instead of `String`.
- `InMemoryPendingStore::Error` is `std::convert::Infallible` (the in-memory store never returns `Err`).
- Role service traits (`PersonTokenService`, `AccessTokenService`, `ResourceAccessService`) are the primary integration API in `aauth`; policy + pending-store orchestration lives in `aauth-policy`.
- Service input contexts (`PersonTokenContext`, `AccessTokenContext`, `ResourceAccessContext`) moved to role modules in `aauth`.
- `mint_person_auth` takes `&AgentClaims` (uses `cnf.jwk`) plus `sub` / `scope` instead of `AuthGrant`.
- HTTP signature verification rebuilds the signature base in `Signature-Input` component order and includes covered headers such as `content-type` (interop with `@hellocoop/httpsig`). Incoming `Signature` values accept standard base64 in addition to URL-safe. `@method` in the signature base uses uppercase.
- `sign_request` includes `content-type` in covered components for POST requests when that header is present.
- JWT claim payload structs (`AgentClaims`, `AuthClaims`, `ResourceClaims`, …) moved from `jwt::claims` to `protocol::jwt`; `jwt` retains decode/verify only.
- `AAuthChallenge` and header build/parse helpers moved from `headers` to `protocol::headers`.
- Pending wire bodies (`PendingBody`, `PendingPostBody`, `PendingStatusBody`, clarification/claims challenges) moved from `deferred`/`types` to `protocol::pending`; `deferred` keeps defer wire outcomes only.
- Crate-root re-exports now source protocol types from `protocol` instead of removed `types` and `headers` modules.
- Restructured `src/` into protocol-party modules: `agent`, `person_server`, `access_server`, `resource`, with shared sibling `deferred`.
- Granular Cargo features per role: `person-server`, `access-server`, `resource`; agent `agent`; meta-features `server` and `full`.
- Renamed features `client` → `agent`; reqwest agent client moved to companion crate `aauth-reqwest` (optional `verify` for 401 challenge binding checks via `resource-verify`).
- `AuthTokenFlowOutcome` / `AuthTokenPollOutcome` moved to `deferred` (shared by Person and Access servers).
- `ResourceAccessMode` lives in `resource::mode` (was `resource::policy`).
- Flat crate-root re-exports are feature-gated to match enabled roles; unused governance wire types stay under `aauth::protocol` only (not crate-root).
- Axum HTTP adapters moved from `aauth` to `aauth-axum`; import handlers/layer/state from `aauth_axum` (examples and axum integration tests live under `aauth-axum/`).
- Reqwest agent client moved from `aauth::agent::reqwest` to `aauth_reqwest`; import `AgentMiddleware`, `sign_request`, etc. from `aauth_reqwest`.
- Collapsed `PersonOrchestrateConfig` into `PersonServerConfig`; token-request verify lives in `person_server::context`.
- Renamed `AuthJwtMinter` → `PersonAuthJwtMinter`, `mint_auth_jwt` → `mint_person_auth_jwt`, `TokenPolicyDecision` → `AccessTokenDecision`.
- Flattened `PersonTokenFlowOutcome` to `Granted` / `Deferred` / `Denied` / `Gone` / `Unauthorized` / `BadGateway` (no nested `Flow`).
- `resource` no longer re-exports `resource_verify`; import verify APIs from `aauth::resource_verify` or the crate root when the feature is on.
- Renamed agent module `injector` → `auth` (`AgentAuth` types unchanged).
- Person Server feature no longer depends on `agent`.
- Person audience URL compare is case-insensitive (matches resource token binding).
- `AgentOptions.metadata_fetcher` is gated on `resource-verify` (enable via `aauth-reqwest` feature `verify`).

### Removed

- Hand-rolled RFC 9421 crypto/base from `aauth::signature` (`build_signature_base_with_extras`, `sign_http_message`, `signing_key_from_jwk`).
- Thin free `TestKeys` wrappers: `create_test_keys`, `static_agent_metadata_fetcher`, `static_person_metadata_fetcher`, free `mint_agent_jwt` / `mint_person_auth_jwt` / `mint_access_auth_jwt`, and `create_key_provider` (use `TestKeys::generate()`, `TestKeys::*_metadata_fetcher`, `TestKeys::mint_*` / `key_provider` instead).
- `aauth` module `policy` and feature `policy` (use crate `aauth-policy`).
- `PendingStore`, `*PendingRecord`, `InMemory*PendingStore`, `Policy*Service`, `OpaqueAccessStore`, and `poll_auth_pending` from `aauth` (use `aauth-policy`).
- `aauth` features `agent-reqwest` and `agent-reqwest-verify` (use crate `aauth-reqwest`).
- `aauth::types` and `aauth::headers` modules (use `aauth::protocol` or flat crate-root re-exports).
- `MetadataDocument` (use `AgentProviderMetadata`).
- `TokenExchangeOptions::localhost_callback` (not a spec token-exchange field).
- `aauth::client` module path (use `aauth::agent`).
- `aauth::server` umbrella module (use role modules or flat re-exports).
- `server` as a single module gate; use per-role features instead.
- `aauth` features `server-axum`, `person-server-axum`, `access-server-axum`, `resource-axum`, and the `server_axum` / `*/axum` modules (use `aauth-axum`).
- Dead helpers: `PersonOrchestrateConfig`, `FederationConfig`, `fulfill_token_exchange`, `map_person_decision_for_aud`, `person_decision_aud_is_ps`, `FixedSubPersonPolicy`, `ResourceAccessPolicy`, `resource_token_audience_unverified`, `AgentAuthStep::Continue`, `resource_poll_outcome_from_snapshot`.
- Unused `PersonServerConfig.agent_url` field.

### Added

- `resource-verify` feature — resource token verification (`verify_resource_token`, `verify_token`, audience resolution) without the full Resource Server service or axum layer.
- `resource_verify` module for token verification used by Person Server federation and optional agent middleware.
- `PersonServerOutboundSigner` and `OutboundSignatureProvider` trait for federation pending POST signing.
- `full` meta-feature matching previous default feature set (roles + agent; axum and reqwest are separate crates).

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
