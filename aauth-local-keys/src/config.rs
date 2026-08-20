use std::path::PathBuf;

use crate::error::{Error, Result};
use crate::types::{AAuthConfig, AgentConfig};

/// Config directory: `AAUTH_DIR` or `~/.aauth`.
pub fn get_config_dir() -> PathBuf {
    if let Ok(dir) = std::env::var("AAUTH_DIR") {
        return PathBuf::from(dir);
    }
    dirs::home_dir()
        .unwrap_or_else(|| PathBuf::from("."))
        .join(".aauth")
}

fn config_file() -> PathBuf {
    get_config_dir().join("config.json")
}

/// Read `config.json`, or `{ agents: {} }` if missing / invalid.
pub fn read_config() -> AAuthConfig {
    let path = config_file();
    let Ok(raw) = std::fs::read_to_string(&path) else {
        return AAuthConfig::default();
    };
    serde_json::from_str(&raw).unwrap_or_default()
}

/// Agent config for `agent_url`, if present.
pub fn get_agent_config(agent_url: &str) -> Option<AgentConfig> {
    read_config().agents.get(agent_url).cloned()
}

/// Agent provider URLs from config.
pub fn list_agent_providers() -> Vec<String> {
    read_config().agents.keys().cloned().collect()
}

/// Person Server URL for an agent, if configured.
pub fn person_server_url(agent_url: &str) -> Option<String> {
    get_agent_config(agent_url)?.person_server_url
}

/// Read config and error if the file exists but is not valid JSON with `agents`.
pub fn read_config_strict() -> Result<AAuthConfig> {
    let path = config_file();
    if !path.exists() {
        return Ok(AAuthConfig::default());
    }
    let raw = std::fs::read_to_string(&path)
        .map_err(|e| Error::Config(format!("read {}: {e}", path.display())))?;
    let config: AAuthConfig = serde_json::from_str(&raw)
        .map_err(|e| Error::Config(format!("parse {}: {e}", path.display())))?;
    Ok(config)
}
