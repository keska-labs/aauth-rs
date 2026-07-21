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

/// Copy reqwest response headers into an `http::HeaderMap`.
#[cfg(feature = "deferred-http")]
pub(crate) fn response_headers_to_http(headers: &reqwest::header::HeaderMap) -> http::HeaderMap {
    let mut map = http::HeaderMap::new();
    for (name, value) in headers.iter() {
        if let (Ok(n), Ok(v)) = (
            http::HeaderName::from_bytes(name.as_str().as_bytes()),
            http::HeaderValue::from_bytes(value.as_bytes()),
        ) {
            map.insert(n, v);
        }
    }
    map
}
