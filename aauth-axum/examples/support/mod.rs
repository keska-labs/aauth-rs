//! Shared helpers for runnable AAuth flow examples.

#![allow(dead_code)]

#[path = "../../tests/support/constants.rs"]
mod constants;

#[path = "../../tests/support/timeout.rs"]
pub mod timeout;

#[path = "../../tests/support/listen.rs"]
mod listen;

#[path = "../../tests/support/client.rs"]
mod client;

#[path = "../../tests/support/metadata.rs"]
mod metadata;

#[path = "../../tests/support/agent_issuer.rs"]
mod agent_issuer;

pub use agent_issuer::agent_issuer_app;
pub use client::AgentClientBuilder;
pub use constants::AGENT_ID;
pub use listen::{bind_ephemeral, serve};
pub use metadata::MultiPartyMetadataFetcher;
