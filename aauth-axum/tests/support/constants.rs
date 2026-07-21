//! Shared test constants.

/// Agent identifier (`aauth:local@domain`).
pub const AGENT_ID: &str = "aauth:test@example.com";

/// Logical agent-provider issuer for JWT `iss` (HTTPS server identifier).
/// Listen URLs stay on `http://127.0.0.1`; StaticMetadataFetcher ignores `iss`.
pub const AGENT_ISSUER: &str = "https://example.com";
