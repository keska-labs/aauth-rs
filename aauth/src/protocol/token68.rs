//! `token68` grammar for opaque `AAuth-Access` / `Authorization: AAuth` credentials.
//!
//! Spec: `draft-hardt-oauth-aauth-protocol.md#aauth-access` (RFC9110 §11.2).

use crate::error::{HeaderError, Result};

/// RFC9110 `token68 = 1*( ALPHA / DIGIT / "-" / "." / "_" / "~" / "+" / "/" ) *"="`
pub fn is_token68(s: &str) -> bool {
    let body = s.trim_end_matches('=');
    !body.is_empty() && body.bytes().all(is_token68_char)
}

fn is_token68_char(b: u8) -> bool {
    b.is_ascii_alphanumeric() || matches!(b, b'-' | b'.' | b'_' | b'~' | b'+' | b'/')
}

/// Parse `Authorization: AAuth <token68>` — single credential only.
///
/// Spec: `draft-hardt-oauth-aauth-protocol.md#aauth-access`
pub fn parse_aauth_credential(authorization_value: &str) -> Result<&str> {
    let token = authorization_value
        .trim()
        .strip_prefix("AAuth ")
        .ok_or_else(|| HeaderError::Invalid("Authorization scheme must be AAuth".into()))?;
    if !is_token68(token) {
        return Err(HeaderError::Invalid("AAuth credential is not token68".into()).into());
    }
    Ok(token)
}

/// Parse an `AAuth-Access` response header value (raw `token68`).
///
/// Spec: `draft-hardt-oauth-aauth-protocol.md#aauth-access`
pub fn parse_aauth_access_header(value: &str) -> Result<&str> {
    let trimmed = value.trim();
    if !is_token68(trimmed) {
        return Err(HeaderError::Invalid("AAuth-Access is not token68".into()).into());
    }
    Ok(trimmed)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn token68_grammar() {
        assert!(is_token68("abcXYZ012-_+/="));
        assert!(is_token68("dGVzdA=="));
        assert!(!is_token68(""));
        assert!(!is_token68("a b"));
        assert!(!is_token68("=abc"));
        assert!(!is_token68("ab?c"));
    }

    #[test]
    fn parse_credential() {
        assert_eq!(parse_aauth_credential("AAuth dGVzdA").unwrap(), "dGVzdA");
        assert!(parse_aauth_credential("AAuth ").is_err());
        assert!(parse_aauth_credential("AAuth a b").is_err());
        assert!(parse_aauth_credential("Bearer dGVzdA").is_err());
    }

    #[test]
    fn parse_access_header() {
        assert_eq!(parse_aauth_access_header("dGVzdA").unwrap(), "dGVzdA");
        assert!(parse_aauth_access_header("").is_err());
        assert!(parse_aauth_access_header("a b").is_err());
    }
}
