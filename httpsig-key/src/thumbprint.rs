//! JWK thumbprint (RFC 7638).

use std::collections::BTreeMap;

use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use sha2::{Digest, Sha256};

use crate::error::{Error, Result};
use crate::protocol::PublicJwk;

pub fn jwk_thumbprint(jwk: &PublicJwk) -> Result<String> {
    let required: &[&str] = match jwk.kty.as_str() {
        "OKP" => &["crv", "kty", "x"],
        "EC" => &["crv", "kty", "x", "y"],
        other => {
            return Err(Error::UnsupportedSigningJwk {
                kty: other.to_string(),
                crv: jwk.crv.clone(),
            });
        }
    };
    let value = serde_json::to_value(jwk)?;
    let obj = value
        .as_object()
        .ok_or_else(|| Error::InvalidJwt("jwk not an object".into()))?;
    let mut members = BTreeMap::new();
    for key in required {
        if let Some(member) = obj.get(*key) {
            members.insert(*key, member.clone());
        }
    }
    let canonical = serde_json::to_string(&members)?;
    let digest = Sha256::digest(canonical.as_bytes());
    Ok(URL_SAFE_NO_PAD.encode(digest))
}
