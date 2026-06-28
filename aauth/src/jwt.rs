use std::collections::BTreeMap;

use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine as _};
use jsonwebtoken::decode_header;
use serde_json::Value;
use sha2::{Digest, Sha256};

use crate::error::{JwtError, Result};
use crate::types::JwtTyp;

pub fn decode_jwt_payload(jwt: &str) -> Result<Value> {
    let parts: Vec<&str> = jwt.split('.').collect();
    if parts.len() != 3 {
        return Err(JwtError::Decode("invalid JWT structure".into()).into());
    }
    let payload = URL_SAFE_NO_PAD
        .decode(parts[1])
        .map_err(|e| JwtError::Decode(e.to_string()))?;
    serde_json::from_slice(&payload).map_err(|e| JwtError::Decode(e.to_string()).into())
}

pub fn jwt_typ(jwt: &str) -> Result<JwtTyp> {
    let header = decode_header(jwt).map_err(|e| JwtError::Decode(e.to_string()))?;
    let typ = header
        .typ
        .ok_or_else(|| JwtError::InvalidTyp("missing typ".into()))?;
    JwtTyp::parse(&typ).ok_or_else(|| JwtError::InvalidTyp(format!("unknown typ: {typ}")).into())
}

pub fn jwk_thumbprint(jwk: &Value) -> Result<String> {
    let canonical = canonical_jwk_for_thumbprint(jwk)?;
    let digest = Sha256::digest(canonical.as_bytes());
    Ok(URL_SAFE_NO_PAD.encode(digest))
}

fn canonical_jwk_for_thumbprint(jwk: &Value) -> Result<String> {
    let obj = jwk
        .as_object()
        .ok_or_else(|| JwtError::Decode("JWK must be an object".into()))?;

    let kty = obj
        .get("kty")
        .and_then(Value::as_str)
        .ok_or_else(|| JwtError::Decode("JWK missing kty".into()))?;

    let required: Vec<&str> = match kty {
        "OKP" => vec!["crv", "kty", "x"],
        "EC" => vec!["crv", "kty", "x", "y"],
        "RSA" => vec!["e", "kty", "n"],
        _ => return Err(JwtError::Decode(format!("unsupported kty: {kty}")).into()),
    };

    let mut members = BTreeMap::new();
    for key in required {
        if let Some(value) = obj.get(key) {
            members.insert(key, value.clone());
        }
    }

    serde_json::to_string(&members).map_err(|e| JwtError::Decode(e.to_string()).into())
}

pub fn signature_key_jwt(token: &str) -> String {
    format!("sig=jwt;jwt=\"{token}\"")
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn thumbprint_is_stable() {
        let jwk = json!({
            "kty": "OKP",
            "crv": "Ed25519",
            "x": "11qYAYKxCrfVS_7TyWQHOg7hcvPapiMlrwIaaPcHURo"
        });
        let tp = jwk_thumbprint(&jwk).unwrap();
        assert!(!tp.is_empty());
        assert_eq!(tp, jwk_thumbprint(&jwk).unwrap());
    }

    #[test]
    fn jwt_typ_round_trip() {
        for typ in [JwtTyp::Agent, JwtTyp::Auth, JwtTyp::Resource] {
            assert_eq!(JwtTyp::parse(typ.as_str()), Some(typ));
        }
        assert_eq!(JwtTyp::parse("unknown"), None);
    }
}
