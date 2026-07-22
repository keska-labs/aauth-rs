#![allow(unused)]

#[cfg(feature = "yubikey")]
mod yubikey_piv;

#[cfg(all(target_os = "macos", feature = "secure-enclave"))]
mod secure_enclave;

// Error::from_reason mirrors napi so backend modules stay stock-shaped.
#[derive(Debug)]
pub struct Error {
    reason: String,
}

impl Error {
    pub fn from_reason(reason: impl Into<String>) -> Self {
        Self {
            reason: reason.into(),
        }
    }
}

impl std::fmt::Display for Error {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.reason)
    }
}

impl std::error::Error for Error {}

pub type Result<T> = std::result::Result<T, Error>;

/// Discovered hardware key backend
pub struct HardwareKeyInfo {
    /// "yubikey-piv" or "secure-enclave"
    pub backend: String,
    /// Human-readable description
    pub description: String,
    /// Supported algorithms: "ES256", "RS256", etc.
    pub algorithms: Vec<String>,
    /// For YubiKey: serial number. For Secure Enclave: "local"
    pub device_id: String,
}

/// Result of key generation
pub struct GeneratedKey {
    /// Backend that holds the key
    pub backend: String,
    /// Key identifier (slot for PIV, tag for Secure Enclave)
    pub key_id: String,
    /// Algorithm used
    pub algorithm: String,
    /// Public key as JWK JSON string
    pub public_jwk: String,
}

/// Result of a signing operation
pub struct SignatureResult {
    /// Raw signature bytes (r||s for ECDSA, raw for RSA)
    pub signature: Vec<u8>,
    /// Algorithm used
    pub algorithm: String,
}

/// Discover available hardware key backends
pub fn discover() -> Vec<HardwareKeyInfo> {
    let mut backends = Vec::new();

    // Check for YubiKey
    #[cfg(feature = "yubikey")]
    if let Some(info) = yubikey_piv::discover() {
        backends.push(info);
    }

    // Check for Secure Enclave (macOS only)
    #[cfg(all(target_os = "macos", feature = "secure-enclave"))]
    if let Some(info) = secure_enclave::discover() {
        backends.push(info);
    }

    backends
}

/// Generate a key on the specified backend
pub fn generate_key(backend: String, algorithm: String) -> Result<GeneratedKey> {
    match backend.as_str() {
        #[cfg(feature = "yubikey")]
        "yubikey-piv" => yubikey_piv::generate_key(&algorithm),
        #[cfg(all(target_os = "macos", feature = "secure-enclave"))]
        "secure-enclave" => secure_enclave::generate_key(&algorithm),
        _ => Err(Error::from_reason(format!("Unknown backend: {}", backend))),
    }
}

/// Sign a hash with a hardware key
/// For JWT: pass the SHA-256 hash of the header.payload string
pub fn sign_hash(backend: String, key_id: String, hash: &[u8]) -> Result<SignatureResult> {
    match backend.as_str() {
        #[cfg(feature = "yubikey")]
        "yubikey-piv" => yubikey_piv::sign_hash(&key_id, hash),
        #[cfg(all(target_os = "macos", feature = "secure-enclave"))]
        "secure-enclave" => secure_enclave::sign_hash(&key_id, hash),
        _ => Err(Error::from_reason(format!("Unknown backend: {}", backend))),
    }
}

/// List existing keys on a backend
pub fn list_keys(backend: String) -> Result<Vec<GeneratedKey>> {
    match backend.as_str() {
        #[cfg(feature = "yubikey")]
        "yubikey-piv" => yubikey_piv::list_keys(),
        #[cfg(all(target_os = "macos", feature = "secure-enclave"))]
        "secure-enclave" => secure_enclave::list_keys(),
        _ => Err(Error::from_reason(format!("Unknown backend: {}", backend))),
    }
}
