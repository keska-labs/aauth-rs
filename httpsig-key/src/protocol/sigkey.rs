//! Accept-Signature `sigkey` parameter values.
//!
//! Spec: `draft-hardt-httpbis-signature-key-05.txt` §4

/// `sigkey` token values from Accept-Signature.
///
/// Spec: `draft-hardt-httpbis-signature-key-05.txt` §4.4
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SigkeyValue {
    /// Pseudonymous / thumbprint-oriented (`jkt`).
    Jkt,
    /// URI-identified keys (`uri`).
    Uri,
    /// X.509 (`x509`).
    X509,
    Other(String),
}

impl SigkeyValue {
    pub fn as_str(&self) -> &str {
        match self {
            Self::Jkt => "jkt",
            Self::Uri => "uri",
            Self::X509 => "x509",
            Self::Other(s) => s.as_str(),
        }
    }

    pub fn parse(token: &str) -> Self {
        match token {
            "jkt" => Self::Jkt,
            "uri" => Self::Uri,
            "x509" => Self::X509,
            other => Self::Other(other.to_string()),
        }
    }
}
