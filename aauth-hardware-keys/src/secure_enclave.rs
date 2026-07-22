/// Secure Enclave backend via [`aauth_macos_se_helper`].
///
/// Label scheme and mapping to [`GeneratedKey`] / [`HardwareKeyInfo`] live here;
/// subprocess I/O is in the helper crate.
use crate::{Error, GeneratedKey, HardwareKeyInfo, Result, SignatureResult};

const AAUTH_KEY_LABEL_PREFIX: &str = "com.aauth.agent.";

/// Check if Secure Enclave is available (helper present and `list` succeeds).
pub fn discover() -> Option<HardwareKeyInfo> {
    #[cfg(target_arch = "aarch64")]
    {
        if !aauth_macos_se_helper::is_available() {
            return None;
        }
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
    let out = aauth_macos_se_helper::generate(&label).map_err(map_err)?;

    Ok(GeneratedKey {
        backend: "secure-enclave".to_string(),
        key_id: out.label,
        algorithm: out.algorithm,
        public_jwk: out.public_jwk,
    })
}

/// Sign a SHA-256 hash with a Secure Enclave key
pub fn sign_hash(key_id: &str, hash: &[u8]) -> Result<SignatureResult> {
    let signature = aauth_macos_se_helper::sign_hash(key_id, hash).map_err(map_err)?;
    Ok(SignatureResult {
        signature,
        algorithm: "ES256".to_string(),
    })
}

/// List keys stored in the Secure Enclave
pub fn list_keys() -> Result<Vec<GeneratedKey>> {
    let items = aauth_macos_se_helper::list().map_err(map_err)?;
    let mut keys = Vec::new();
    for item in items {
        let public_jwk =
            aauth_macos_se_helper::public_key(&item.label).unwrap_or_else(|_| "{}".into());
        keys.push(GeneratedKey {
            backend: "secure-enclave".to_string(),
            key_id: item.label,
            algorithm: if item.algorithm.is_empty() {
                "ES256".to_string()
            } else {
                item.algorithm
            },
            public_jwk,
        });
    }
    Ok(keys)
}

fn map_err(e: aauth_macos_se_helper::Error) -> Error {
    Error::from_reason(e.to_string())
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
