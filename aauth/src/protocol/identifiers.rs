//! Server and agent identifier validation.
//!
//! Spec: `draft-hardt-oauth-aauth-protocol.md#server-identifiers`,
//! `#agent-identifiers`

use url::Url;

/// Returns true if `url` is a valid AAuth server identifier.
///
/// MUST be `https`, scheme + host only (no port, path, query, fragment, or
/// trailing slash), and lowercase.
///
/// Also accepts loopback HTTP (`http://127.0.0.1[:port]`, `http://localhost[:port]`)
/// for local integration tests.
pub fn is_valid_server_identifier(url: &str) -> bool {
    if is_loopback_http_identifier(url) {
        return true;
    }
    if url.is_empty() || url.ends_with('/') {
        return false;
    }
    // Spec requires lowercase; reject any ASCII uppercase in the raw string.
    if url.chars().any(|c| c.is_ascii_uppercase()) {
        return false;
    }
    let Ok(parsed) = Url::parse(url) else {
        return false;
    };
    if parsed.scheme() != "https" {
        return false;
    }
    if parsed.port().is_some() {
        return false;
    }
    if !parsed.username().is_empty() || parsed.password().is_some() {
        return false;
    }
    if parsed.query().is_some() || parsed.fragment().is_some() {
        return false;
    }
    // `url` normalizes host-only URLs to path "/". Reject real paths and
    // trailing-slash inputs (already rejected above via `ends_with('/')`).
    if parsed.path() != "/" && !parsed.path().is_empty() {
        return false;
    }
    parsed.host_str().is_some_and(|host| !host.is_empty())
}

fn is_loopback_http_identifier(url: &str) -> bool {
    if url.is_empty() || url.ends_with('/') {
        return false;
    }
    let Ok(parsed) = Url::parse(url) else {
        return false;
    };
    if parsed.scheme() != "http" {
        return false;
    }
    if parsed.query().is_some() || parsed.fragment().is_some() {
        return false;
    }
    if parsed.path() != "/" && !parsed.path().is_empty() {
        return false;
    }
    if !parsed.username().is_empty() || parsed.password().is_some() {
        return false;
    }
    matches!(parsed.host_str(), Some("127.0.0.1" | "localhost"))
}

/// Returns true if `id` is a valid AAuth agent identifier (`aauth:local@domain`).
pub fn is_valid_agent_identifier(id: &str) -> bool {
    let Some(rest) = id.strip_prefix("aauth:") else {
        return false;
    };
    let Some((local, domain)) = rest.split_once('@') else {
        return false;
    };
    if local.is_empty() || local.len() > 255 {
        return false;
    }
    if !local
        .chars()
        .all(|c| matches!(c, 'a'..='z' | '0'..='9' | '-' | '_' | '+' | '.'))
    {
        return false;
    }
    is_valid_domain_name(domain)
}

fn is_valid_domain_name(domain: &str) -> bool {
    if domain.is_empty() || domain.chars().any(|c| c.is_ascii_uppercase()) {
        return false;
    }
    if domain.contains("://") || domain.contains('/') || domain.contains(':') {
        return false;
    }
    // Must look like a hostname (at least one label).
    domain.split('.').all(|label| {
        !label.is_empty()
            && label.len() <= 63
            && label
                .chars()
                .all(|c| matches!(c, 'a'..='z' | '0'..='9' | '-'))
            && !label.starts_with('-')
            && !label.ends_with('-')
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn server_identifier_examples() {
        assert!(is_valid_server_identifier("https://agent.example"));
        assert!(is_valid_server_identifier("https://xn--nxasmq6b.example"));
        assert!(!is_valid_server_identifier("http://agent.example"));
        assert!(!is_valid_server_identifier("https://Agent.Example"));
        assert!(!is_valid_server_identifier("https://agent.example:8443"));
        assert!(!is_valid_server_identifier("https://agent.example/v1"));
        assert!(!is_valid_server_identifier("https://agent.example/"));
        assert!(is_valid_server_identifier("http://127.0.0.1:18765"));
        assert!(is_valid_server_identifier("http://localhost"));
        assert!(!is_valid_server_identifier("http://example.com"));
    }

    #[test]
    fn agent_identifier_examples() {
        assert!(is_valid_agent_identifier(
            "aauth:assistant-v2@agent.example"
        ));
        assert!(is_valid_agent_identifier(
            "aauth:planner.7f3c@vendor.example"
        ));
        assert!(is_valid_agent_identifier(
            "aauth:planner.7f3c+search1@vendor.example"
        ));
        assert!(!is_valid_agent_identifier("My Agent@agent.example"));
        assert!(!is_valid_agent_identifier("@agent.example"));
        assert!(!is_valid_agent_identifier("agent@http://agent.example"));
        assert!(!is_valid_agent_identifier("aauth:@agent.example"));
    }
}
