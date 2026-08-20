use std::io::Write;
use std::sync::{Mutex, OnceLock};

use aauth_local_keys::{
    get_agent_config, list_agent_providers, read_config, read_config_strict, AAuthConfig,
    AgentConfig, LocalKeyMeta,
};
use aauth_local_keys::{KeyAlgorithm, KeyBackend};

fn env_lock() -> &'static Mutex<()> {
    static LOCK: OnceLock<Mutex<()>> = OnceLock::new();
    LOCK.get_or_init(|| Mutex::new(()))
}

#[test]
fn read_config_missing_is_empty() {
    let _guard = env_lock().lock().unwrap();
    let dir = tempfile::tempdir().unwrap();
    unsafe { std::env::set_var("AAUTH_DIR", dir.path()) };
    let config = read_config();
    assert!(config.agents.is_empty());
    unsafe { std::env::remove_var("AAUTH_DIR") };
}

#[test]
fn read_config_parses_agents() {
    let _guard = env_lock().lock().unwrap();
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("config.json");
    let mut f = std::fs::File::create(&path).unwrap();
    write!(
        f,
        r#"{{
  "agents": {{
    "https://you.github.io": {{
      "agentId": "aauth:local@you.github.io",
      "personServerUrl": "https://ps.example",
      "keys": {{
        "2026-04-09_a3f": {{
          "backend": "secure-enclave",
          "algorithm": "ES256",
          "keyId": "com.aauth.agent.2026-04-09",
          "deviceLabel": "macbook"
        }}
      }}
    }}
  }}
}}"#
    )
    .unwrap();

    unsafe { std::env::set_var("AAUTH_DIR", dir.path()) };

    let providers = list_agent_providers();
    assert_eq!(providers, vec!["https://you.github.io".to_string()]);

    let agent = get_agent_config("https://you.github.io").unwrap();
    assert_eq!(
        agent.agent_id.as_deref(),
        Some("aauth:local@you.github.io")
    );
    assert_eq!(agent.person_server_url.as_deref(), Some("https://ps.example"));
    let meta = agent.keys.get("2026-04-09_a3f").unwrap();
    assert_eq!(meta.backend, KeyBackend::SecureEnclave);
    assert_eq!(meta.algorithm, KeyAlgorithm::ES256);
    assert_eq!(meta.key_id, "com.aauth.agent.2026-04-09");

    let strict = read_config_strict().unwrap();
    assert_eq!(strict.agents.len(), 1);

    unsafe { std::env::remove_var("AAUTH_DIR") };
}

#[test]
fn key_backend_roundtrip() {
    assert_eq!(KeyBackend::parse("yubikey-piv"), Some(KeyBackend::YubikeyPiv));
    assert_eq!(KeyBackend::SecureEnclave.as_str(), "secure-enclave");
    assert!(KeyBackend::YubikeyPiv.is_hardware());
    assert!(!KeyBackend::Software.is_hardware());
}

#[test]
fn config_serde_defaults() {
    let cfg: AAuthConfig = serde_json::from_str(r#"{"agents":{}}"#).unwrap();
    assert!(cfg.agents.is_empty());

    let agent: AgentConfig = serde_json::from_str(r#"{}"#).unwrap();
    assert!(agent.keys.is_empty());

    let meta: LocalKeyMeta = serde_json::from_str(
        r#"{"backend":"software","algorithm":"EdDSA","keyId":"k1","deviceLabel":"local"}"#,
    )
    .unwrap();
    assert_eq!(meta.backend, KeyBackend::Software);
}

#[test]
fn create_agent_token_requires_agent_url() {
    let _guard = env_lock().lock().unwrap();
    let dir = tempfile::tempdir().unwrap();
    unsafe { std::env::set_var("AAUTH_DIR", dir.path()) };

    let err = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .unwrap()
        .block_on(aauth_local_keys::create_agent_token(Default::default()))
        .unwrap_err();
    assert!(
        matches!(err, aauth_local_keys::Error::NoAgentUrl),
        "{err}"
    );

    unsafe { std::env::remove_var("AAUTH_DIR") };
}

#[test]
fn create_agent_token_requires_agent_id() {
    let _guard = env_lock().lock().unwrap();
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("config.json");
    std::fs::write(
        &path,
        r#"{"agents":{"https://you.github.io":{"keys":{}}}}"#,
    )
    .unwrap();
    unsafe { std::env::set_var("AAUTH_DIR", dir.path()) };

    let err = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .unwrap()
        .block_on(aauth_local_keys::create_agent_token(
            aauth_local_keys::CreateAgentTokenOptions {
                agent_url: Some("https://you.github.io".into()),
                ..Default::default()
            },
        ))
        .unwrap_err();
    assert!(
        matches!(err, aauth_local_keys::Error::NoAgentId(_)),
        "{err}"
    );

    unsafe { std::env::remove_var("AAUTH_DIR") };
}

#[test]
fn discover_includes_software_backend() {
    let backends = aauth_local_keys::discover_backends();
    assert!(backends.iter().any(|b| b.backend == KeyBackend::Software));
}

#[cfg(all(target_os = "macos", target_arch = "aarch64"))]
#[test]
#[ignore = "live Secure Enclave / keychain access"]
fn secure_enclave_list_keys_smoke() {
    let backends = aauth_local_keys::discover_backends();
    if !backends
        .iter()
        .any(|b| b.backend == KeyBackend::SecureEnclave)
    {
        return;
    }
    let keys = aauth_hardware_keys::list_keys("secure-enclave".into()).expect("list SE keys");
    let _ = keys;
}
