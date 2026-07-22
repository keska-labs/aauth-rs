# aauth-reqwest

Reqwest transport adapters for AAuth:

- **Agent client** — wraps [`aauth::agent::auth::AgentAuth`] with HTTP: request signing, resource-token exchange at the Person Server, deferred (`202`) polling, and optional proactive `authorization_endpoint` POSTs.
- **Person Server federation** (feature `person-server`) — [`ReqwestAccessServerClient`] implements [`aauth::AccessServerClient`] for PS→AS metadata, token exchange, and pending resume/poll.

Domain types and state machines live in [`aauth`](https://docs.rs/aauth); this crate is the reqwest adapter.

**Pre-alpha.** Breaking changes are expected.

## Install

```toml
aauth = { version = "0.0", default-features = false, features = ["agent"] }
aauth-reqwest = { version = "0.0" }

# Person Server federation client:
aauth-reqwest = { version = "0.0", features = ["person-server"] }
```

For the agent path, challenge verification always runs before token exchange; auth-token claim binding always runs after exchange. JWT signature verification of returned auth tokens defaults **on** ([`AgentOptions::verify_auth_signature`](https://docs.rs/aauth/latest/aauth/agent/auth/struct.AgentOptions.html)); provide a [`MetadataFetcher`](https://docs.rs/aauth/latest/aauth/metadata/trait.MetadataFetcher.html) (for example [`CachedMetadataFetcher`]) so JWKS discovery works.

## Quick start

Use [`TestKeys`](https://docs.rs/aauth/latest/aauth/keys/struct.TestKeys.html) in development, or implement [`KeyMaterialProvider`](https://docs.rs/aauth/latest/aauth/agent/keys/trait.KeyMaterialProvider.html) for production key material:

```rust,no_run
use aauth::TestKeys;
use aauth_reqwest::{AgentMiddleware, AgentOptions, ClientBuilder};

# #[tokio::main]
# async fn main() -> Result<(), Box<dyn std::error::Error>> {
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

// Signing + challenge handling are automatic.
let identity = client
    .get("https://whoami.aauth.dev")
    .send()
    .await?
    .text()
    .await?;
println!("{identity}");

let scoped = client
    .get("https://whoami.aauth.dev?scope=openid+profile")
    .send()
    .await?
    .text()
    .await?;
println!("{scoped}");
# Ok(())
# }
```

## What the middleware does

On each response, [`AgentAuth`](https://docs.rs/aauth/latest/aauth/agent/auth/struct.AgentAuth.html) returns an [`AgentAuthStep`](https://docs.rs/aauth/latest/aauth/agent/auth/enum.AgentAuthStep.html). [`AgentMiddleware`] drives that loop:

1. Sign the outbound request (see also [`RequestSigningExt`] for one-off signing)
2. On `401` + `AAuth-Requirement` with a resource token → [`exchange_token`] at the Person Server
3. On `202` + `Location` → [`poll_deferred`] until an auth token or failure
4. Retry the original request with a cached auth or opaque token when appropriate

Configure interaction / clarification callbacks and poll limits on [`AgentOptions`](https://docs.rs/aauth/latest/aauth/agent/auth/struct.AgentOptions.html) / [`AgentDeferredOptions`].

## Person Server federation

With feature `person-server`, construct a [`ReqwestAccessServerClient`] from a `reqwest::Client` and [`PersonServerOutboundSigner`](https://docs.rs/aauth/latest/aauth/struct.PersonServerOutboundSigner.html), then set it as `PersonServerConfig.access_server`.

## Re-exports

This crate re-exports the agent options and auth types you need at the call site (`AgentOptions`, `AgentAuth`, callbacks, …) plus `reqwest` / `reqwest_middleware` for building the client. See the module list below for the full surface.

## See also

- Servers: [`aauth-axum`](https://docs.rs/aauth-axum)
- Policy helpers: [`aauth-policy`](https://docs.rs/aauth-policy)
- Spec: [AAuth protocol draft](https://github.com/keska-labs/aauth-rs/blob/main/docs/specs/draft-hardt-oauth-aauth-protocol.md)
