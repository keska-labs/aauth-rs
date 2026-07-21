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
    pub fn to_header(&self) -> String {
        match &self.description {
            Some(d) => format!("error=\"{}\"; description=\"{}\"", self.error, d),
            None => format!("error=\"{}\"", self.error),
        }
    }

    pub fn from_header(header: &str) -> Option<Self> {
        let mut error = None;
        let mut description = None;
        for part in header.split(';') {
            let part = part.trim();
            if let Some(v) = part.strip_prefix("error=\"") {
                error = Some(v.trim_end_matches('"').to_string());
            } else if let Some(v) = part.strip_prefix("description=\"") {
                description = Some(v.trim_end_matches('"').to_string());
            }
        }
        Some(Self {
            error: error?,
            description,
        })
    }
}
