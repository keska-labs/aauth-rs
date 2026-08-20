//! Build artifact + typed client for the adhoc-codesigned `se-helper` CLI.
//!
//! On macOS aarch64, `build.rs` compiles `swift/main.swift`, codesigns it, and
//! copies it to `target/{debug,release}/se-helper`. Public functions spawn that
//! binary (packages-js argv/JSON protocol).

use std::env;
use std::fmt;
use std::path::PathBuf;
use std::process::{Command, Stdio};
use std::time::{Duration, Instant};

use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
use serde::Deserialize;
use serde_json::Value;

const HELPER_TIMEOUT: Duration = Duration::from_secs(10);

/// Error from locating or invoking `se-helper`.
#[derive(Debug)]
pub struct Error {
    message: String,
}

impl Error {
    fn msg(message: impl Into<String>) -> Self {
        Self {
            message: message.into(),
        }
    }
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.message)
    }
}

impl std::error::Error for Error {}

pub type Result<T> = std::result::Result<T, Error>;

/// Result of `se-helper generate`.
#[derive(Debug, Clone)]
pub struct GenerateOutput {
    pub label: String,
    pub algorithm: String,
    /// Public JWK as a JSON object string.
    pub public_jwk: String,
}

/// One entry from `se-helper list`.
#[derive(Debug, Clone, Deserialize)]
pub struct KeyInfo {
    pub label: String,
    #[serde(default)]
    pub algorithm: String,
    #[serde(default)]
    pub backend: String,
}

/// Resolve the `se-helper` binary path.
///
/// Lookup order:
/// 1. `AAUTH_SE_HELPER` environment variable
/// 2. Compile-time path from this crate's `build.rs` (`AAUTH_SE_HELPER_PATH`)
/// 3. `se-helper` next to the current executable
pub fn helper_path() -> Option<PathBuf> {
    if let Ok(p) = env::var("AAUTH_SE_HELPER") {
        let p = PathBuf::from(p);
        if p.is_file() {
            return Some(p);
        }
    }

    #[cfg(all(target_os = "macos", target_arch = "aarch64"))]
    {
        if let Some(p) = option_env!("AAUTH_SE_HELPER_PATH") {
            let p = PathBuf::from(p);
            if p.is_file() {
                return Some(p);
            }
        }
        if let Ok(exe) = env::current_exe() {
            if let Some(dir) = exe.parent() {
                let p = dir.join("se-helper");
                if p.is_file() {
                    return Some(p);
                }
            }
        }
    }

    None
}

/// Whether the helper is present and responds to `list`.
pub fn is_available() -> bool {
    helper_path().is_some() && list().is_ok()
}

/// Create a P-256 key for `label`; returns public JWK JSON.
pub fn generate(label: &str) -> Result<GenerateOutput> {
    let value = call(&["generate", label])?;
    let public_jwk = value
        .get("publicJwk")
        .ok_or_else(|| Error::msg("se-helper generate missing publicJwk"))?;
    let public_jwk = serde_json::to_string(public_jwk)
        .map_err(|e| Error::msg(format!("serialize publicJwk: {e}")))?;
    let algorithm = value
        .get("algorithm")
        .and_then(|v| v.as_str())
        .unwrap_or("ES256")
        .to_string();
    let out_label = value
        .get("label")
        .and_then(|v| v.as_str())
        .unwrap_or(label)
        .to_string();
    Ok(GenerateOutput {
        label: out_label,
        algorithm,
        public_jwk,
    })
}

/// Sign a 32-byte SHA-256 digest; returns raw ECDSA r||s.
pub fn sign_hash(label: &str, hash: &[u8]) -> Result<Vec<u8>> {
    if hash.len() != 32 {
        return Err(Error::msg(format!(
            "Expected 32-byte SHA-256 digest, got {}",
            hash.len()
        )));
    }
    let hex = bytes_to_hex(hash);
    let value = call(&["sign", label, &hex])?;
    let sig_b64 = value
        .get("signature")
        .and_then(|v| v.as_str())
        .ok_or_else(|| Error::msg("se-helper sign missing signature"))?;
    URL_SAFE_NO_PAD
        .decode(sig_b64.as_bytes())
        .map_err(|e| Error::msg(format!("decode signature: {e}")))
}

/// List Secure Enclave keys managed by the helper.
pub fn list() -> Result<Vec<KeyInfo>> {
    let value = call(&["list"])?;
    serde_json::from_value(value).map_err(|e| Error::msg(format!("parse list: {e}")))
}

/// Public JWK JSON object string for an existing key label.
pub fn public_key(label: &str) -> Result<String> {
    let value = call(&["public-key", label])?;
    let jwk = value
        .get("publicJwk")
        .ok_or_else(|| Error::msg("se-helper public-key missing publicJwk"))?;
    serde_json::to_string(jwk).map_err(|e| Error::msg(format!("serialize publicJwk: {e}")))
}

/// Delete a key by label.
pub fn delete(label: &str) -> Result<()> {
    let _ = call(&["delete", label])?;
    Ok(())
}

fn call(args: &[&str]) -> Result<Value> {
    let helper = helper_path().ok_or_else(|| {
        Error::msg(
            "se-helper binary not found (build aauth-macos-se-helper on macOS aarch64, or set AAUTH_SE_HELPER)",
        )
    })?;

    let mut child = Command::new(&helper)
        .args(args)
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .map_err(|e| Error::msg(format!("spawn se-helper: {e}")))?;

    let deadline = Instant::now() + HELPER_TIMEOUT;
    let status = loop {
        match child.try_wait() {
            Ok(Some(status)) => break status,
            Ok(None) if Instant::now() < deadline => {
                std::thread::sleep(Duration::from_millis(10));
            }
            Ok(None) => {
                let _ = child.kill();
                let _ = child.wait();
                return Err(Error::msg("se-helper timed out after 10s"));
            }
            Err(e) => return Err(Error::msg(format!("wait se-helper: {e}"))),
        }
    };

    let mut stdout = Vec::new();
    let mut stderr = Vec::new();
    if let Some(mut out) = child.stdout.take() {
        use std::io::Read;
        out.read_to_end(&mut stdout)
            .map_err(|e| Error::msg(format!("read se-helper stdout: {e}")))?;
    }
    if let Some(mut err) = child.stderr.take() {
        use std::io::Read;
        err.read_to_end(&mut stderr)
            .map_err(|e| Error::msg(format!("read se-helper stderr: {e}")))?;
    }

    if !status.success() {
        let stderr = String::from_utf8_lossy(&stderr);
        let msg = stderr.trim();
        return Err(Error::msg(if msg.is_empty() {
            format!("se-helper exited with {status}")
        } else {
            msg.to_string()
        }));
    }

    let stdout = String::from_utf8_lossy(&stdout);
    let trimmed = stdout.trim();
    if trimmed.is_empty() {
        return Err(Error::msg("se-helper returned empty stdout"));
    }
    serde_json::from_str(trimmed)
        .map_err(|e| Error::msg(format!("parse se-helper JSON: {e}: {trimmed}")))
}

fn bytes_to_hex(bytes: &[u8]) -> String {
    let mut s = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        s.push_str(&format!("{b:02x}"));
    }
    s
}
