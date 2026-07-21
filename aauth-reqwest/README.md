# aauth-reqwest

Reqwest transport for the AAuth **agent** client.

Wraps [`aauth::agent::auth::AgentAuth`] with HTTP: request signing, resource-token exchange at the Person Server, deferred (`202`) polling, and optional proactive `authorization_endpoint` POSTs. Domain types and the auth state machine live in [`aauth`](https://docs.rs/aauth); this crate is the reqwest adapter.

**Pre-alpha.** Breaking changes are expected.

## Install

```toml
aauth = { version = "0.0", default-features = false, features = ["agent"] }
aauth-reqwest = { version = "0.0" }
```

No optional features. Challenge verification always runs before token exchange; auth-token claim binding always runs after exchange. JWT signature verification of returned auth tokens defaults **on** ([`AgentOptions::verify_auth_signature`](https://docs.rs/aauth/latest/aauth/agent/auth/struct.AgentOptions.html)); provide a [`MetadataFetcher`](https://docs.rs/aauth/latest/aauth/metadata/trait.MetadataFetcher.html) (for example [`CachedMetadataFetcher`]) so JWKS discovery works.

## Quick start

Use [`TestKeys`](https://docs.rs/aauth/latest/aauth/keys/struct.TestKeys.html) in development, or implement [`KeyMaterialProvider`](https://docs.rs/aauth/latest/aauth/agent/keys/trait.KeyMaterialProvider.html) for production key material:

```rust
use aauth::TestKeys;
use aauth_reqwest::{AgentMiddleware, AgentOptions, ClientBuilder};

fn main() {
let keys = TestKeys::generate();
let issuer = "https://example.com";
let agent_jwt = keys.mint_agent_jwt(issuer, "aauth:test@example.com", None);

let client = ClientBuilder::new(reqwest::Client::new())
    .with(AgentMiddleware::new(
        AgentOptions::builder(keys.key_provider(agent_jwt))
            .metadata_fetcher(keys.agent_metadata_fetcher(issuer))
            // person_server_url omitted → resolved from agent JWT `ps` when challenged
            .build(),
    ))
    .build();

// Ready to call a protected resource (signing + challenge handling are automatic).
let _ = client;
}
```

## What the middleware does

On each response, [`AgentAuth`](https://docs.rs/aauth/latest/aauth/agent/auth/struct.AgentAuth.html) returns an [`AgentAuthStep`](https://docs.rs/aauth/latest/aauth/agent/auth/enum.AgentAuthStep.html). [`AgentMiddleware`] drives that loop:

1. Sign the outbound request (see also [`RequestSigningExt`] for one-off signing)
2. On `401` + `AAuth-Requirement` with a resource token → [`exchange_token`] at the Person Server
3. On `202` + `Location` → [`poll_deferred`] until an auth token or failure
4. Retry the original request with a cached auth or opaque token when appropriate

Configure interaction / clarification callbacks and poll limits on [`AgentOptions`](https://docs.rs/aauth/latest/aauth/agent/auth/struct.AgentOptions.html) / [`AgentDeferredOptions`].

## Re-exports

This crate re-exports the agent options and auth types you need at the call site (`AgentOptions`, `AgentAuth`, callbacks, …) plus `reqwest` / `reqwest_middleware` for building the client. See the module list below for the full surface.

## See also

- Servers: [`aauth-axum`](https://docs.rs/aauth-axum)
- Policy helpers: [`aauth-policy`](https://docs.rs/aauth-policy)
- Spec: [AAuth protocol draft](https://github.com/keska-labs/aauth-rs/blob/main/docs/specs/draft-hardt-oauth-aauth-protocol.md)
