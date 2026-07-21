//! Small shared HTTP helpers used across roles.

use http::HeaderMap;
use http::header::HeaderName;

/// Trim trailing `/` and lowercase for URL equality checks (audience / issuer binding).
pub(crate) fn normalize_server_url(url: &str) -> String {
    url.trim_end_matches('/').to_lowercase()
}

pub(crate) fn header_value<'a>(headers: &'a HeaderMap, name: &HeaderName) -> Option<&'a str> {
    headers.get(name).and_then(|v| v.to_str().ok())
}
