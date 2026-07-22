/// Secure Enclave backend via the Cargo-built `se-helper` CLI subprocess.
///
/// Mirrors `@aauth/local-keys` `backends/secure-enclave.ts`: argv commands and
/// JSON stdout. The helper is built and adhoc-codesigned by `aauth-macos-se-ffi`.
use std::process::{Command, Stdio};
use std::time::{Duration, Instant};

use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};
use serde_json::Value;

use crate::{Error, GeneratedKey, HardwareKeyInfo, Result, SignatureResult};

const AAUTH_KEY_LABEL_PREFIX: &str = "com.aauth.agent.";
const HELPER_TIMEOUT: Duration = Duration::from_secs(10);

/// Check if Secure Enclave is available (helper present and `list` succeeds).
pub fn discover() -> Option<HardwareKeyInfo> {
    #[cfg(target_arch = "aarch64")]
    {
        aauth_macos_se_ffi::helper_path()?;
        call_helper(&["list"]).ok()?;
        Some(HardwareKeyInfo {
            backend: "secure-enclave".to_string(),
            description: "macOS Secure Enclave (Apple Silicon)".to_string(),
            algorithms: vec!["ES256".to_string()],
            device_id: "local".to_string(),
        })
    }

    #[cfg(not(target_arch = "aarch64"))]
    {
        None
    }
}

/// Generate a P-256 key in the Secure Enclave
pub fn generate_key(algorithm: &str) -> Result<GeneratedKey> {
    if algorithm != "ES256" {
        return Err(Error::from_reason(
            "Secure Enclave only supports ES256 (P-256)",
        ));
    }

    let label = format!("{}{}_{}", AAUTH_KEY_LABEL_PREFIX, iso_date(), random_hex3());
    let result = call_helper(&["generate", &label])?;
    let public_jwk = result
        .get("publicJwk")
        .ok_or_else(|| Error::from_reason("se-helper generate missing publicJwk"))?;
    let public_jwk = serde_json::to_string(public_jwk)
        .map_err(|e| Error::from_reason(format!("serialize publicJwk: {e}")))?;

    Ok(GeneratedKey {
        backend: "secure-enclave".to_string(),
        key_id: label,
        algorithm: "ES256".to_string(),
        public_jwk,
    })
}

/// Sign a SHA-256 hash with a Secure Enclave key
pub fn sign_hash(key_id: &str, hash: &[u8]) -> Result<SignatureResult> {
    if hash.len() != 32 {
        return Err(Error::from_reason(format!(
            "Expected 32-byte SHA-256 digest, got {}",
            hash.len()
        )));
    }
    let hex = bytes_to_hex(hash);
    let result = call_helper(&["sign", key_id, &hex])?;
    let sig_b64 = result
        .get("signature")
        .and_then(|v| v.as_str())
        .ok_or_else(|| Error::from_reason("se-helper sign missing signature"))?;
    let signature = URL_SAFE_NO_PAD
        .decode(sig_b64.as_bytes())
        .map_err(|e| Error::from_reason(format!("decode signature: {e}")))?;

    Ok(SignatureResult {
        signature,
        algorithm: "ES256".to_string(),
    })
}

/// List keys stored in the Secure Enclave
pub fn list_keys() -> Result<Vec<GeneratedKey>> {
    let result = call_helper(&["list"])?;
    let items = result
        .as_array()
        .ok_or_else(|| Error::from_reason("se-helper list did not return an array"))?;

    let mut keys = Vec::new();
    for item in items {
        let label = item
            .get("label")
            .and_then(|v| v.as_str())
            .ok_or_else(|| Error::from_reason("se-helper list item missing label"))?;
        let public_jwk = match call_helper(&["public-key", label]) {
            Ok(pk) => pk
                .get("publicJwk")
                .map(|j| serde_json::to_string(j).unwrap_or_else(|_| "{}".into()))
                .unwrap_or_else(|| "{}".into()),
            Err(_) => "{}".into(),
        };
        keys.push(GeneratedKey {
            backend: "secure-enclave".to_string(),
            key_id: label.to_string(),
            algorithm: "ES256".to_string(),
            public_jwk,
        });
    }
    Ok(keys)
}

fn call_helper(args: &[&str]) -> Result<Value> {
    let helper = aauth_macos_se_ffi::helper_path().ok_or_else(|| {
        Error::from_reason(
            "se-helper binary not found (build aauth-macos-se-ffi on macOS aarch64, or set AAUTH_SE_HELPER)",
        )
    })?;

    // Soft 10s wall clock: poll try_wait then read pipes (same budget as packages-js).
    let mut child = Command::new(&helper)
        .args(args)
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .map_err(|e| Error::from_reason(format!("spawn se-helper: {e}")))?;

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
                return Err(Error::from_reason("se-helper timed out after 10s"));
            }
            Err(e) => return Err(Error::from_reason(format!("wait se-helper: {e}"))),
        }
    };

    let mut stdout = Vec::new();
    let mut stderr = Vec::new();
    if let Some(mut out) = child.stdout.take() {
        use std::io::Read;
        out.read_to_end(&mut stdout)
            .map_err(|e| Error::from_reason(format!("read se-helper stdout: {e}")))?;
    }
    if let Some(mut err) = child.stderr.take() {
        use std::io::Read;
        err.read_to_end(&mut stderr)
            .map_err(|e| Error::from_reason(format!("read se-helper stderr: {e}")))?;
    }

    if !status.success() {
        let stderr = String::from_utf8_lossy(&stderr);
        let msg = stderr.trim();
        return Err(Error::from_reason(if msg.is_empty() {
            format!("se-helper exited with {status}")
        } else {
            msg.to_string()
        }));
    }

    let stdout = String::from_utf8_lossy(&stdout);
    let trimmed = stdout.trim();
    if trimmed.is_empty() {
        return Err(Error::from_reason("se-helper returned empty stdout"));
    }
    serde_json::from_str(trimmed)
        .map_err(|e| Error::from_reason(format!("parse se-helper JSON: {e}: {trimmed}")))
}

fn bytes_to_hex(bytes: &[u8]) -> String {
    let mut s = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        s.push_str(&format!("{b:02x}"));
    }
    s
}

fn iso_date() -> String {
    use std::time::{SystemTime, UNIX_EPOCH};
    let secs = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0);
    let days = secs / 86400;
    let (y, m, d) = civil_from_days(days as i64);
    format!("{y:04}-{m:02}-{d:02}")
}

/// Howard Hinnant civil_from_days (proleptic Gregorian).
fn civil_from_days(z: i64) -> (i32, u32, u32) {
    let z = z + 719468;
    let era = if z >= 0 { z } else { z - 146096 } / 146097;
    let doe = (z - era * 146097) as u64;
    let yoe = (doe - doe / 1460 + doe / 36524 - doe / 146096) / 365;
    let y = (yoe as i64) + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = doy - (153 * mp + 2) / 5 + 1;
    let m = if mp < 10 { mp + 3 } else { mp - 9 };
    let y = if m <= 2 { y + 1 } else { y };
    (y as i32, m as u32, d as u32)
}

fn random_hex3() -> String {
    use std::collections::hash_map::DefaultHasher;
    use std::hash::{Hash, Hasher};
    use std::time::{SystemTime, UNIX_EPOCH};
    let mut h = DefaultHasher::new();
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_nanos())
        .unwrap_or(0)
        .hash(&mut h);
    std::process::id().hash(&mut h);
    format!("{:03x}", h.finish() & 0xfff)
}
