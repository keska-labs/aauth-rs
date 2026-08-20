use keyring::Entry;

use crate::error::{Error, Result};
use crate::types::KeychainData;

const SERVICE: &str = "aauth";

/// Read software keys for `agent_url` from the OS keychain.
pub fn read_keychain(agent_url: &str) -> Result<Option<KeychainData>> {
    let entry = Entry::new(SERVICE, agent_url)
        .map_err(|e| Error::Keychain(e.to_string()))?;
    match entry.get_password() {
        Ok(raw) => {
            let data: KeychainData = serde_json::from_str(&raw)?;
            Ok(Some(data))
        }
        Err(keyring::Error::NoEntry) => Ok(None),
        Err(e) => Err(Error::Keychain(e.to_string())),
    }
}
