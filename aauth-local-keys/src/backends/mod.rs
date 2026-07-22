use serde_json::{Map, Value};

use crate::error::{Error, Result};
use crate::keychain::read_keychain;
use crate::types::{KeyAlgorithm, KeyBackend};

#[cfg(feature = "hardware")]
use aauth_hardware_keys::{self as hardware};

/// Discovered backend (mirrors JS `BackendInfo`).
#[derive(Debug, Clone)]
pub struct BackendInfo {
    pub backend: KeyBackend,
    pub description: String,
    pub algorithms: Vec<KeyAlgorithm>,
    pub device_id: String,
}

/// A local key with public material for matching.
#[derive(Debug, Clone)]
pub struct LocalKey {
    pub backend: KeyBackend,
    pub key_id: String,
    pub kid: String,
    pub algorithm: KeyAlgorithm,
    pub public_jwk: Value,
    pub thumbprint: String,
}

/// Discover available key backends on this machine.
pub fn discover_backends() -> Vec<BackendInfo> {
    let mut backends = vec![BackendInfo {
        backend: KeyBackend::Software,
        description: "Software keys stored in OS keychain".into(),
        algorithms: vec![KeyAlgorithm::EdDSA, KeyAlgorithm::ES256],
        device_id: "local".into(),
    }];

    #[cfg(feature = "hardware")]
    {
        for info in hardware::discover() {
            if let Some(backend) = KeyBackend::parse(&info.backend) {
                let algorithms = info
                    .algorithms
                    .iter()
                    .filter_map(|a| KeyAlgorithm::parse(a))
                    .collect();
                backends.push(BackendInfo {
                    backend,
                    description: info.description,
                    algorithms,
                    device_id: info.device_id,
                });
            }
        }
    }

    backends
}

/// List local keys for resolution. Always includes software keys for `agent_url`.
pub fn discover_local_keys(agent_url: &str) -> Vec<LocalKey> {
    let mut keys = Vec::new();

    // Software keys for this agent (and any we can find).
    if let Ok(Some(data)) = read_keychain(agent_url) {
        for (kid, jwk) in &data.keys {
            if let Some(local) = software_local_key(kid, jwk) {
                keys.push(local);
            }
        }
    }

    #[cfg(feature = "hardware")]
    {
        for info in discover_backends() {
            if !info.backend.is_hardware() {
                continue;
            }
            let backend_id = info.backend.as_str();
            let listed = hardware::list_keys(backend_id.into()).unwrap_or_default();
            for generated in listed {
                if let Some(local) = hardware_local_key(info.backend, &generated) {
                    keys.push(local);
                }
            }
        }
    }

    keys
}

fn software_local_key(kid: &str, jwk: &Value) -> Option<LocalKey> {
    let mut pub_jwk = strip_private(jwk);
    let alg = algorithm_from_jwk(jwk)?;
    if pub_jwk.get("alg").is_none() {
        pub_jwk["alg"] = Value::String(alg.as_str().into());
    }
    if pub_jwk.get("use").is_none() {
        pub_jwk["use"] = Value::String("sig".into());
    }
    let thumbprint = thumbprint_value(&pub_jwk).ok()?;
    let kid = jwk
        .get("kid")
        .and_then(|v| v.as_str())
        .unwrap_or(kid)
        .to_string();
    Some(LocalKey {
        backend: KeyBackend::Software,
        key_id: kid.clone(),
        kid,
        algorithm: alg,
        public_jwk: pub_jwk,
        thumbprint,
    })
}

#[cfg(feature = "hardware")]
fn hardware_local_key(backend: KeyBackend, generated: &hardware::GeneratedKey) -> Option<LocalKey> {
    let public_jwk: Value = serde_json::from_str(&generated.public_jwk).ok()?;
    if public_jwk.get("kty").is_none() {
        return None;
    }
    let algorithm = KeyAlgorithm::parse(&generated.algorithm)?;
    let thumbprint = thumbprint_value(&public_jwk).ok()?;
    let kid = public_jwk
        .get("kid")
        .and_then(|v| v.as_str())
        .unwrap_or(&generated.key_id)
        .to_string();
    Some(LocalKey {
        backend,
        key_id: generated.key_id.clone(),
        kid,
        algorithm,
        public_jwk,
        thumbprint,
    })
}

/// Load public JWK for a config-registered hardware key (lazy path).
pub fn get_public_key(backend: KeyBackend, key_id: &str) -> Result<Value> {
    match backend {
        KeyBackend::Software => {
            // Caller should have agent context; scan is limited without enumeration.
            Err(Error::msg(format!("Software key not found: {key_id}")))
        }
        #[cfg(feature = "hardware")]
        KeyBackend::YubikeyPiv => public_jwk_from_list("yubikey-piv", key_id),
        #[cfg(feature = "hardware")]
        KeyBackend::SecureEnclave => public_jwk_from_list("secure-enclave", key_id),
        #[cfg(not(feature = "hardware"))]
        KeyBackend::YubikeyPiv | KeyBackend::SecureEnclave => Err(Error::msg(
            "hardware backends disabled (build with default features)",
        )),
    }
}

#[cfg(feature = "hardware")]
fn public_jwk_from_list(backend: &str, key_id: &str) -> Result<Value> {
    let keys = hardware::list_keys(backend.into())?;
    let key = keys
        .into_iter()
        .find(|k| k.key_id == key_id)
        .ok_or_else(|| Error::msg(format!("Key not found: backend={backend} key_id={key_id}")))?;
    Ok(serde_json::from_str(&key.public_jwk)?)
}

/// Sign JWT signing input with a hardware key.
pub fn hardware_sign(backend: KeyBackend, key_id: &str, signing_input: &[u8]) -> Result<Vec<u8>> {
    #[cfg(feature = "hardware")]
    {
        use sha2::{Digest, Sha256};
        let hash = Sha256::digest(signing_input);
        match backend {
            KeyBackend::SecureEnclave => {
                #[cfg(all(target_os = "macos", target_arch = "aarch64"))]
                {
                    let result = hardware::sign_hash(
                        "secure-enclave".into(),
                        key_id.into(),
                        hash.as_slice(),
                    )?;
                    Ok(result.signature)
                }
                #[cfg(not(all(target_os = "macos", target_arch = "aarch64")))]
                {
                    let _ = key_id;
                    Err(Error::msg(
                        "Secure Enclave is only available on macOS Apple Silicon",
                    ))
                }
            }
            KeyBackend::YubikeyPiv => {
                let result =
                    hardware::sign_hash("yubikey-piv".into(), key_id.into(), hash.as_slice())?;
                Ok(result.signature)
            }
            KeyBackend::Software => Err(Error::msg(
                "Software backend does not use hardware_sign",
            )),
        }
    }
    #[cfg(not(feature = "hardware"))]
    {
        let _ = (backend, key_id, signing_input);
        Err(Error::msg(
            "hardware backends disabled (build with default features)",
        ))
    }
}

pub fn strip_private(jwk: &Value) -> Value {
    let mut map = Map::new();
    if let Some(obj) = jwk.as_object() {
        for (k, v) in obj {
            if k != "d" {
                map.insert(k.clone(), v.clone());
            }
        }
    }
    Value::Object(map)
}

pub fn algorithm_from_jwk(jwk: &Value) -> Option<KeyAlgorithm> {
    if let Some(alg) = jwk.get("alg").and_then(|v| v.as_str()) {
        return KeyAlgorithm::parse(alg);
    }
    match jwk.get("crv").and_then(|v| v.as_str()) {
        Some("P-256") => Some(KeyAlgorithm::ES256),
        Some("Ed25519") => Some(KeyAlgorithm::EdDSA),
        _ => None,
    }
}

pub fn thumbprint_value(jwk: &Value) -> Result<String> {
    let public = value_to_public_jwk(jwk)?;
    httpsig_key::jwk_thumbprint(&public).map_err(|e| Error::msg(e.to_string()))
}

pub fn value_to_public_jwk(jwk: &Value) -> Result<httpsig_key::PublicJwk> {
    let kty = jwk
        .get("kty")
        .and_then(|v| v.as_str())
        .ok_or_else(|| Error::msg("JWK missing kty"))?
        .to_string();
    let crv = jwk
        .get("crv")
        .and_then(|v| v.as_str())
        .ok_or_else(|| Error::msg("JWK missing crv"))?
        .to_string();
    let x = jwk
        .get("x")
        .and_then(|v| v.as_str())
        .ok_or_else(|| Error::msg("JWK missing x"))?
        .to_string();
    let y = jwk
        .get("y")
        .and_then(|v| v.as_str())
        .map(str::to_string);
    let kid = jwk
        .get("kid")
        .and_then(|v| v.as_str())
        .map(str::to_string);
    Ok(httpsig_key::PublicJwk {
        kty,
        crv,
        x,
        y,
        kid,
    })
}

pub fn value_to_signing_jwk(jwk: &Value) -> Result<httpsig_key::SigningJwk> {
    let public = value_to_public_jwk(jwk)?;
    let d = jwk
        .get("d")
        .and_then(|v| v.as_str())
        .ok_or_else(|| Error::msg("JWK missing private key d"))?
        .to_string();
    Ok(httpsig_key::SigningJwk {
        kty: public.kty,
        crv: public.crv,
        x: public.x,
        y: public.y,
        d,
        kid: public.kid,
    })
}
