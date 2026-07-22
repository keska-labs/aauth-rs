//! Load AAuth agent signing keys from `~/.aauth`, the OS keychain, and hardware backends.
//!
//! Mirrors [`@aauth/local-keys`](https://github.com/aauth-dev/packages-js/tree/main/local-keys).
//! Hardware backends come from the vendored [`aauth-hardware-keys`] crate.
//!
//! ```ignore
//! use aauth::AgentOptions;
//! use aauth_local_keys::LocalKeysProvider;
//!
//! let provider = LocalKeysProvider::builder().build();
//! let options = AgentOptions::builder(provider).build();
//! ```

mod agent_token;
mod backends;
mod config;
mod create_agent_token;
mod error;
mod keychain;
mod provider;
mod resolve;
mod types;

pub use agent_token::sign_agent_token;
pub use backends::{discover_backends, BackendInfo};
pub use config::{
    get_agent_config, get_config_dir, list_agent_providers, person_server_url, read_config,
    read_config_strict,
};
pub use create_agent_token::{create_agent_token, CreateAgentTokenOptions};
pub use error::{Error, Result};
pub use keychain::read_keychain;
pub use provider::{LocalKeysProvider, LocalKeysProviderBuilder};
pub use resolve::resolve_key;
pub use types::{
    AAuthConfig, AgentConfig, AgentTokenResult, KeyAlgorithm, KeyBackend, KeychainData,
    LocalKeyMeta, ResolvedKey, SignatureKeyJwt, SignAgentTokenOptions,
};
