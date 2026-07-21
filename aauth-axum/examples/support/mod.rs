//! Shared helpers for runnable AAuth flow examples.

#![allow(dead_code)]

#[path = "../../tests/support/constants.rs"]
mod constants;

#[path = "../../tests/support/harness_policy.rs"]
mod harness_policy;

#[path = "../../tests/support/harness_access_policy.rs"]
mod harness_access_policy;

#[path = "../../tests/support/harness_resource_policy.rs"]
mod harness_resource_policy;

#[path = "../../tests/support/timeout.rs"]
mod timeout;

#[path = "../../tests/support/axum_server.rs"]
mod axum_server;

#[path = "../../tests/support/client.rs"]
mod client;

pub use axum_server::{TestScenario, spawn_test_server};
pub use constants::AGENT_ID;
