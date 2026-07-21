//! `Signature-Error` response header.
//!
//! Spec: `draft-hardt-httpbis-signature-key-05.txt` §5

/// Parsed `Signature-Error` header content (simplified).
///
/// Spec: `draft-hardt-httpbis-signature-key-05.txt` §5.1, §5.4
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SignatureErrorHeader {
    pub error: String,
    pub description: Option<String>,
}

impl SignatureErrorHeader {
    /// Build a bare `error=<token>` header (no description).
    pub fn new(error: impl Into<String>) -> Self {
        Self {
            error: error.into(),
            description: None,
        }
    }

    /// Serialize as an SFV Dictionary Token member: `error=invalid_signature`.
    ///
    /// Spec: `draft-hardt-httpbis-signature-key-05.txt` §5.1
    pub fn to_header(&self) -> String {
        match &self.description {
            Some(d) => format!("error={}; description=\"{}\"", self.error, d),
            None => format!("error={}", self.error),
        }
    }

    pub fn from_header(header: &str) -> Option<Self> {
        let mut error = None;
        let mut description = None;
        for part in header.split(';') {
            let part = part.trim();
            if let Some(v) = part.strip_prefix("error=") {
                let v = v.trim();
                error = Some(
                    v.strip_prefix('"')
                        .and_then(|s| s.strip_suffix('"'))
                        .unwrap_or(v)
                        .to_string(),
                );
            } else if let Some(v) = part.strip_prefix("description=") {
                let v = v.trim();
                description = Some(
                    v.strip_prefix('"')
                        .and_then(|s| s.strip_suffix('"'))
                        .unwrap_or(v)
                        .to_string(),
                );
            }
        }
        Some(Self {
            error: error?,
            description,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sfv_token_roundtrip() {
        let h = SignatureErrorHeader::new("invalid_signature");
        assert_eq!(h.to_header(), "error=invalid_signature");
        assert_eq!(SignatureErrorHeader::from_header(&h.to_header()), Some(h));
    }
}
