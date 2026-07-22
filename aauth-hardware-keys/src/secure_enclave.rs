/// Thin Rust bridge to in-process se-helper (`swift/SecureEnclaveBridge.swift`).
///
/// Mirrors how `@aauth/local-keys` `backends/secure-enclave.ts` shells out to
/// `se-helper` (`generate` / `sign` with hex hash / `list` / `public-key`).
use std::ffi::{CStr, CString};
use std::os::raw::c_char;
use std::ptr;

use crate::{Error, GeneratedKey, HardwareKeyInfo, Result, SignatureResult};

const AAUTH_KEY_LABEL_PREFIX: &str = "com.aauth.agent.";

unsafe extern "C" {
    fn aauth_se_is_available() -> bool;
    fn aauth_se_free(ptr: *mut std::ffi::c_void);
    fn aauth_se_generate(
        label: *const c_char,
        out_jwk_json: *mut *mut c_char,
        error_out: *mut *mut c_char,
    ) -> bool;
    fn aauth_se_sign_hash(
        label: *const c_char,
        hex_hash: *const c_char,
        out_sig: *mut *mut u8,
        out_sig_len: *mut usize,
        error_out: *mut *mut c_char,
    ) -> bool;
    fn aauth_se_public_key(
        label: *const c_char,
        out_jwk_json: *mut *mut c_char,
        error_out: *mut *mut c_char,
    ) -> bool;
    fn aauth_se_list(out_labels: *mut *mut c_char, error_out: *mut *mut c_char) -> bool;
}

fn take_c_string(ptr: *mut c_char) -> String {
    if ptr.is_null() {
        return String::new();
    }
    let s = unsafe { CStr::from_ptr(ptr) }
        .to_string_lossy()
        .into_owned();
    unsafe { aauth_se_free(ptr.cast()) };
    s
}

fn take_error(ok: bool, err: *mut c_char) -> Result<()> {
    if ok {
        if !err.is_null() {
            unsafe { aauth_se_free(err.cast()) };
        }
        Ok(())
    } else {
        let msg = if err.is_null() {
            "unknown Secure Enclave error".into()
        } else {
            take_c_string(err)
        };
        Err(Error::from_reason(msg))
    }
}

fn take_bytes(ok: bool, ptr: *mut u8, len: usize, err: *mut c_char) -> Result<Vec<u8>> {
    take_error(ok, err)?;
    let bytes = if ptr.is_null() || len == 0 {
        Vec::new()
    } else {
        unsafe { std::slice::from_raw_parts(ptr, len) }.to_vec()
    };
    if !ptr.is_null() {
        unsafe { aauth_se_free(ptr.cast()) };
    }
    Ok(bytes)
}

fn c_string(s: &str) -> Result<CString> {
    CString::new(s).map_err(|_| Error::from_reason("CString contains NUL"))
}

fn bytes_to_hex(bytes: &[u8]) -> String {
    let mut s = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        s.push_str(&format!("{b:02x}"));
    }
    s
}

/// Check if Secure Enclave is available
pub fn discover() -> Option<HardwareKeyInfo> {
    #[cfg(target_arch = "aarch64")]
    {
        if !unsafe { aauth_se_is_available() } {
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

    // Same label scheme as @aauth/local-keys secure-enclave.ts
    let label = format!("{}{}_{}", AAUTH_KEY_LABEL_PREFIX, iso_date(), random_hex3());
    let c_label = c_string(&label)?;

    let mut jwk_ptr = ptr::null_mut();
    let mut err = ptr::null_mut();
    let ok = unsafe { aauth_se_generate(c_label.as_ptr(), &mut jwk_ptr, &mut err) };
    take_error(ok, err)?;
    let public_jwk = take_c_string(jwk_ptr);
    if public_jwk.is_empty() {
        return Err(Error::from_reason("SE generate returned empty JWK"));
    }

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
    // se-helper / secure-enclave.ts pass the digest as hex
    let hex = bytes_to_hex(hash);
    let c_label = c_string(key_id)?;
    let c_hex = c_string(&hex)?;

    let mut sig_ptr = ptr::null_mut();
    let mut sig_len = 0usize;
    let mut err = ptr::null_mut();
    let ok = unsafe {
        aauth_se_sign_hash(
            c_label.as_ptr(),
            c_hex.as_ptr(),
            &mut sig_ptr,
            &mut sig_len,
            &mut err,
        )
    };
    let signature = take_bytes(ok, sig_ptr, sig_len, err)?;
    Ok(SignatureResult {
        signature,
        algorithm: "ES256".to_string(),
    })
}

/// List keys stored in the Secure Enclave with our label prefix
pub fn list_keys() -> Result<Vec<GeneratedKey>> {
    let labels = list_labels()?;
    let mut keys = Vec::new();
    for label in labels {
        let public_jwk = match public_jwk_for_label(&label) {
            Ok(jwk) => jwk,
            Err(_) => "{}".to_string(),
        };
        keys.push(GeneratedKey {
            backend: "secure-enclave".to_string(),
            key_id: label,
            algorithm: "ES256".to_string(),
            public_jwk,
        });
    }
    Ok(keys)
}

fn public_jwk_for_label(label: &str) -> Result<String> {
    let c_label = c_string(label)?;
    let mut jwk_ptr = ptr::null_mut();
    let mut err = ptr::null_mut();
    let ok = unsafe { aauth_se_public_key(c_label.as_ptr(), &mut jwk_ptr, &mut err) };
    take_error(ok, err)?;
    let json = take_c_string(jwk_ptr);
    if json.is_empty() {
        return Err(Error::from_reason("SE public-key returned empty JWK"));
    }
    Ok(json)
}

fn list_labels() -> Result<Vec<String>> {
    let mut labels_ptr = ptr::null_mut();
    let mut err = ptr::null_mut();
    let ok = unsafe { aauth_se_list(&mut labels_ptr, &mut err) };
    take_error(ok, err)?;
    let joined = take_c_string(labels_ptr);
    if joined.is_empty() {
        return Ok(Vec::new());
    }
    Ok(joined.split('\n').map(str::to_string).collect())
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
