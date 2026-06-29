//! Shared helpers for runnable AAuth flow examples.

#[path = "../../tests/support/axum_server.rs"]
mod axum_server;

#[path = "../../tests/support/client.rs"]
mod client;

pub use axum_server::{ServerConfig, spawn_test_server};
pub use client::build_client;
