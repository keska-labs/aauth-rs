//! Live E2E against [whoami.aauth.dev](https://whoami.aauth.dev) via `aauth-reqwest`.
//!
//! Prefer the `@aauth/fetch` CLI interop tests in `aauth-axum` (`fetch_person_server`)
//! when validating JS client ↔ Rust server. This suite keeps a Rust-client path.
//!
//! Prerequisites:
//! - `npx @aauth/bootstrap create <agent-provider-url>` with JWKS published
//! - Ed25519 (software EdDSA) or P-256 ES256 (e.g. Secure Enclave) ephemeral key
//! - Node/`npx` on `PATH`
//!
//! Run:
//! ```bash
//! cargo test -p aauth-reqwest --test whoami_e2e -- --ignored --nocapture
//! ```

use std::path::PathBuf;
use std::process::Command;
use std::sync::Arc;

use aauth::{KeyMaterial, SignatureKey, SignatureKeyJwt, SigningJwk, StaticKeyMaterialProvider};
use aauth_reqwest::{AgentMiddleware, AgentOptions, ClientBuilder};
use serde::Deserialize;
use serde_json::Value;

const WHOAMI: &str = "https://whoami.aauth.dev";
const WHOAMI_SCOPED: &str = "https://whoami.aauth.dev?scope=email+profile";

#[derive(Debug, Deserialize)]
struct BootstrapToken {
    #[serde(rename = "signingKey")]
    signing_key: Value,
    #[serde(rename = "signatureKey")]
    signature_key: BootstrapSignatureKey,
}

#[derive(Debug, Deserialize)]
struct BootstrapSignatureKey {
    #[serde(rename = "type")]
    key_type: String,
    jwt: String,
}

#[derive(Debug, Deserialize)]
struct AauthConfig {
    agents: std::collections::HashMap<String, AgentConfig>,
}

#[derive(Debug, Deserialize)]
struct AgentConfig {
    #[serde(rename = "personServerUrl")]
    person_server_url: Option<String>,
}

fn aauth_dir() -> PathBuf {
    if let Ok(dir) = std::env::var("AAUTH_DIR") {
        return PathBuf::from(dir);
    }
    let home = std::env::var("HOME").expect(
        "HOME unset and AAUTH_DIR unset — set AAUTH_DIR to your @aauth/bootstrap config root",
    );
    PathBuf::from(home).join(".aauth")
}

fn read_person_server_url() -> Option<String> {
    let path = aauth_dir().join("config.json");
    let raw = std::fs::read_to_string(&path).ok()?;
    let cfg: AauthConfig = serde_json::from_str(&raw).ok()?;
    cfg.agents.into_values().find_map(|a| a.person_server_url)
}

fn load_bootstrap_token() -> BootstrapToken {
    let output = Command::new("npx")
        .args(["--yes", "@aauth/bootstrap", "token"])
        .env("NO_COLOR", "1")
        .output()
        .unwrap_or_else(|e| {
            panic!(
                "failed to run `npx @aauth/bootstrap token` ({e}). \
                 Install Node and run `npx @aauth/bootstrap create <url>` first."
            )
        });

    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        panic!(
            "`npx @aauth/bootstrap token` failed (exit {}). \
             Run `npx @aauth/bootstrap list` / `create`. stderr:\n{stderr}",
            output.status
        );
    }

    let stdout = String::from_utf8_lossy(&output.stdout);
    serde_json::from_str(stdout.trim())
        .unwrap_or_else(|e| panic!("failed to parse bootstrap token JSON ({e}). stdout:\n{stdout}"))
}

fn provider_from_bootstrap() -> Arc<aauth::DynKeyMaterialProvider<'static>> {
    let token = load_bootstrap_token();
    assert_eq!(
        token.signature_key.key_type, "jwt",
        "bootstrap token signatureKey.type must be jwt"
    );

    let signing_jwk: SigningJwk =
        serde_json::from_value(token.signing_key.clone()).unwrap_or_else(|e| {
            panic!(
                "bootstrap signingKey is not a supported signing JWK ({e}). Got: {}",
                token.signing_key
            )
        });

    match (signing_jwk.kty.as_str(), signing_jwk.crv.as_str()) {
        ("OKP", "Ed25519") => {}
        ("EC", "P-256") => {
            assert!(
                signing_jwk.y.is_some(),
                "ES256 signing key missing y coordinate"
            );
        }
        (kty, crv) => panic!(
            "unsupported bootstrap signing key kty={kty} crv={crv}; \
             need OKP/Ed25519 or EC/P-256"
        ),
    }

    StaticKeyMaterialProvider::new(KeyMaterial {
        signing_jwk,
        signature_key: SignatureKey::Jwt(SignatureKeyJwt {
            jwt: token.signature_key.jwt,
        }),
    })
    .into_arc()
}

#[rstest::fixture]
#[once]
fn client() -> aauth_reqwest::ClientWithMiddleware {
    let provider = provider_from_bootstrap();
    let mut builder = AgentOptions::builder(provider)
        .on_interaction(Arc::new(|url, code| {
            eprintln!("Approve at: {url}?code={code}");
        }))
        .max_poll_duration_secs(900);

    if let Some(ps) = read_person_server_url() {
        builder = builder.person_server_url(ps);
    }

    ClientBuilder::new(reqwest::Client::new())
        .with(AgentMiddleware::new(builder.build()))
        .build()
}

#[rstest::rstest]
#[case::unscoped(WHOAMI)]
#[case::scoped(WHOAMI_SCOPED)]
#[tokio::test]
#[ignore = "live whoami; needs bootstrap + human consent"]
async fn whoami_agentic_fetch(client: &aauth_reqwest::ClientWithMiddleware, #[case] url: &str) {
    let response = client
        .get(url)
        .send()
        .await
        .unwrap_or_else(|e| panic!("request to {url} failed: {e}"));
    let status = response.status();
    let body = response
        .text()
        .await
        .unwrap_or_else(|e| panic!("reading body from {url}: {e}"));

    assert!(status.is_success(), "{url} returned {status}: {body}");
    let json: Value = serde_json::from_str(&body)
        .unwrap_or_else(|e| panic!("expected JSON from {url} ({e}): {body}"));

    assert!(
        json.get("sub").and_then(|v| v.as_str()).is_some(),
        "whoami response missing sub: {json}"
    );
}
