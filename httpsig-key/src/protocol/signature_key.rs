//! `Signature-Key` schemes and signing material.
//!
//! Spec: `draft-hardt-httpbis-signature-key-05.txt` §3

use super::jwk::{PublicJwk, SigningJwk};
use crate::error::{Error, Result};

/// `Signature-Key` header value using `scheme=jwt`.
///
/// Spec: `draft-hardt-httpbis-signature-key-05.txt` §3.6
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SignatureKeyJwt {
    pub jwt: String,
}

/// `Signature-Key` header value using `scheme=hwk`.
///
/// Spec: `draft-hardt-httpbis-signature-key-05.txt` §3.3
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SignatureKeyHwk {
    pub jwk: PublicJwk,
}

/// Parsed `Signature-Key` scheme for one label.
///
/// Spec: `draft-hardt-httpbis-signature-key-05.txt` §3
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SignatureKey {
    Jwt(SignatureKeyJwt),
    Hwk(SignatureKeyHwk),
    /// Unsupported in v1 (`jkt-jwt`, `jwks_uri`, `x509`, …).
    Unsupported(SignatureKeyScheme),
}

/// Known scheme tokens from the draft.
///
/// Spec: `draft-hardt-httpbis-signature-key-05.txt` §3.3–§3.7
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SignatureKeyScheme {
    Hwk,
    JktJwt,
    JwksUri,
    Jwt,
    X509,
    Other(String),
}

impl SignatureKeyScheme {
    pub fn as_str(&self) -> &str {
        match self {
            Self::Hwk => "hwk",
            Self::JktJwt => "jkt-jwt",
            Self::JwksUri => "jwks_uri",
            Self::Jwt => "jwt",
            Self::X509 => "x509",
            Self::Other(s) => s.as_str(),
        }
    }

    pub fn parse(token: &str) -> Self {
        match token {
            "hwk" => Self::Hwk,
            "jkt-jwt" => Self::JktJwt,
            "jwks_uri" => Self::JwksUri,
            "jwt" => Self::Jwt,
            "x509" => Self::X509,
            other => Self::Other(other.to_string()),
        }
    }
}

/// Local signing key bound to a `Signature-Key` presentation.
#[derive(Debug, Clone)]
pub struct SigningMaterial {
    pub signing_jwk: SigningJwk,
    pub signature_key: SignatureKey,
}

impl SignatureKey {
    /// Serialize one dictionary member value (`jwt;jwt="..."` or `hwk;…`).
    ///
    /// Spec: `draft-hardt-httpbis-signature-key-05.txt` §3
    pub fn to_member_value(&self) -> Result<String> {
        match self {
            Self::Jwt(j) => Ok(format!("jwt;jwt=\"{}\"", j.jwt)),
            Self::Hwk(h) => {
                let mut parts = vec![
                    "hwk".to_string(),
                    format!("kty=\"{}\"", h.jwk.kty),
                    format!("crv=\"{}\"", h.jwk.crv),
                    format!("x=\"{}\"", h.jwk.x),
                ];
                if let Some(y) = &h.jwk.y {
                    parts.push(format!("y=\"{y}\""));
                }
                if let Some(kid) = &h.jwk.kid {
                    parts.push(format!("kid=\"{kid}\""));
                }
                Ok(parts.join(";"))
            }
            Self::Unsupported(scheme) => Err(Error::UnsupportedScheme(scheme.as_str().to_string())),
        }
    }

    /// Full `Signature-Key` header for label `sig`.
    pub fn to_header(&self, label: &str) -> Result<String> {
        Ok(format!("{label}={}", self.to_member_value()?))
    }

    /// Parse a `Signature-Key` header, returning the member for `label` (default `sig`).
    pub fn from_header(header: &str, label: &str) -> Result<Self> {
        // Minimal parse: `label=scheme;param="value";…`
        let prefix = format!("{label}=");
        let start = header
            .find(&prefix)
            .ok_or_else(|| Error::InvalidSignatureKey(format!("label `{label}` not found")))?;
        let rest = &header[start + prefix.len()..];
        // Truncate at next top-level comma (multi-sig).
        let member = rest.split(',').next().unwrap_or(rest).trim();
        parse_member(member)
    }
}

fn parse_member(member: &str) -> Result<SignatureKey> {
    let mut parts = member.split(';');
    let scheme_token = parts
        .next()
        .ok_or_else(|| Error::InvalidSignatureKey("empty member".into()))?
        .trim();
    let scheme = SignatureKeyScheme::parse(scheme_token);

    match scheme {
        SignatureKeyScheme::Jwt => {
            let mut jwt = None;
            for part in parts {
                let part = part.trim();
                if let Some(v) = part.strip_prefix("jwt=\"") {
                    let end = v.find('"').ok_or(Error::MissingJwtParam)?;
                    jwt = Some(v[..end].to_string());
                }
            }
            let jwt = jwt.ok_or(Error::MissingJwtParam)?;
            Ok(SignatureKey::Jwt(SignatureKeyJwt { jwt }))
        }
        SignatureKeyScheme::Hwk => {
            let mut kty = None;
            let mut crv = None;
            let mut x = None;
            let mut y = None;
            let mut kid = None;
            for part in parts {
                let part = part.trim();
                if let Some((k, v)) = part.split_once('=') {
                    let v = v.trim().trim_matches('"');
                    match k.trim() {
                        "kty" => kty = Some(v.to_string()),
                        "crv" => crv = Some(v.to_string()),
                        "x" => x = Some(v.to_string()),
                        "y" => y = Some(v.to_string()),
                        "kid" => kid = Some(v.to_string()),
                        _ => {}
                    }
                }
            }
            Ok(SignatureKey::Hwk(SignatureKeyHwk {
                jwk: PublicJwk {
                    kty: kty.ok_or_else(|| Error::InvalidSignatureKey("hwk missing kty".into()))?,
                    crv: crv.ok_or_else(|| Error::InvalidSignatureKey("hwk missing crv".into()))?,
                    x: x.ok_or_else(|| Error::InvalidSignatureKey("hwk missing x".into()))?,
                    y,
                    kid,
                },
            }))
        }
        other => Ok(SignatureKey::Unsupported(other)),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn jwt_roundtrip_header() {
        let key = SignatureKey::Jwt(SignatureKeyJwt {
            jwt: "abc.def.ghi".into(),
        });
        let header = key.to_header("sig").unwrap();
        assert_eq!(header, "sig=jwt;jwt=\"abc.def.ghi\"");
        let parsed = SignatureKey::from_header(&header, "sig").unwrap();
        assert_eq!(parsed, key);
    }

    #[test]
    fn hwk_roundtrip_header() {
        let key = SignatureKey::Hwk(SignatureKeyHwk {
            jwk: PublicJwk {
                kty: "OKP".into(),
                crv: "Ed25519".into(),
                x: "JrQLj5P".into(),
                y: None,
                kid: None,
            },
        });
        let header = key.to_header("sig").unwrap();
        let parsed = SignatureKey::from_header(&header, "sig").unwrap();
        assert_eq!(parsed, key);
    }
}
