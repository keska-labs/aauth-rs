# aauth-local-keys

Load AAuth agent signing keys from `~/.aauth`, the OS keychain, and hardware
backends — the Rust equivalent of
[`@aauth/local-keys`](https://github.com/aauth-dev/packages-js/tree/main/local-keys).

Hardware backends live in the vendored
[`aauth-hardware-keys`](../aauth-hardware-keys) crate (YubiKey PIV and
macOS Secure Enclave).

## Install

```toml
aauth-local-keys = { path = "../aauth-local-keys" } # or crates.io when published
```

Default features enable hardware backends. Use `default-features = false` for
software/keychain-only builds.

## Usage with the agent

```rust
use aauth::AgentOptions;
use aauth_local_keys::LocalKeysProvider;

let provider = LocalKeysProvider::builder()
    // Optional: defaults to first agent in ~/.aauth/config.json
    // .agent_url("https://you.github.io")
    .build();

let options = AgentOptions::builder(provider)
    // person_server_url may also come from config / agent JWT `ps`
    .build();
```

Or mint material directly:

```rust
use aauth_local_keys::{create_agent_token, CreateAgentTokenOptions};

# async fn demo() -> aauth_local_keys::Result<()> {
let token = create_agent_token(CreateAgentTokenOptions {
    agent_url: Some("https://you.github.io".into()),
    ..Default::default()
})
.await?;
// token.signing_key — ephemeral private JWK for HTTP Message Signatures
// token.signature_key.jwt — agent JWT
# Ok(())
# }
```

## Key resolution

Same fallback chain as the JS package (hardware preferred):

1. Fetch `{agentUrl}/.well-known/aauth-agent.json` → JWKS, match local thumbprints
2. Keys registered in `~/.aauth/config.json` (`AAUTH_DIR` overrides the directory)
3. First available local hardware key
4. First software key in the OS keychain (`service = "aauth"`)

## Secure Enclave

SE matches `@aauth/bootstrap` / se-helper: CryptoKit blobs in keychain
`service=com.aauth.secure-enclave`, implemented in-process in
`aauth-hardware-keys` (Swift bridge; needs `swiftc`). Enrollment stays with
bootstrap.

## License

MIT OR Apache-2.0
