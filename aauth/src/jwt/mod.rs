mod claims;
mod decode;

pub use claims::{
    ActClaim, AgentClaims, AuthClaims, CnfClaim, OkpJwk, VerifiedToken,
};
pub use decode::{decode_unverified, decode_verified, verified_validation};

use std::collections::BTreeMap;

use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine as _};
use jsonwebtoken::decode_header;
use sha2::{Digest, Sha256};

use crate::error::{JwtError, Result};
use crate::types::JwtTyp;

impl JwtTyp {
    /// Reads and parses the JWT `typ` header.
    pub fn from_jwt(jwt: &str) -> Result<Self> {
        let header = decode_header(jwt).map_err(|e| JwtError::Decode(e.to_string()))?;
        let typ = header
            .typ
            .ok_or_else(|| JwtError::InvalidTyp("missing typ".into()))?;
        typ.parse()
            .map_err(|_| JwtError::InvalidTyp(format!("unknown typ: {typ}")).into())
    }
}

pub fn jwk_thumbprint(jwk: &OkpJwk) -> Result<String> {
    let canonical = canonical_jwk_for_thumbprint(jwk)?;
    let digest = Sha256::digest(canonical.as_bytes());
    Ok(URL_SAFE_NO_PAD.encode(digest))
}

fn canonical_jwk_for_thumbprint(jwk: &OkpJwk) -> Result<String> {
    let kty = jwk.kty.as_str();

    let required: Vec<&str> = match kty {
        "OKP" => vec!["crv", "kty", "x"],
        "EC" => vec!["crv", "kty", "x", "y"],
        "RSA" => vec!["e", "kty", "n"],
        _ => return Err(JwtError::Decode(format!("unsupported kty: {kty}")).into()),
    };

    let value = serde_json::to_value(jwk).map_err(|e| JwtError::Decode(e.to_string()))?;
    let obj = value
        .as_object()
        .ok_or_else(|| JwtError::Decode("JWK must be an object".into()))?;

    let mut members = BTreeMap::new();
    for key in required {
        if let Some(member) = obj.get(key) {
            members.insert(key, member.clone());
        }
    }

    serde_json::to_string(&members).map_err(|e| JwtError::Decode(e.to_string()).into())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::str::FromStr;

    #[test]
    fn thumbprint_is_stable() {
        let jwk = OkpJwk {
            kty: "OKP".into(),
            crv: "Ed25519".into(),
            x: "11qYAYKxCrfVS_7TyWQHOg7hcvPapiMlrwIaaPcHURo".into(),
            kid: None,
        };
        let tp = jwk_thumbprint(&jwk).unwrap();
        assert!(!tp.is_empty());
        assert_eq!(tp, jwk_thumbprint(&jwk).unwrap());
    }

    #[test]
    fn jwt_typ_from_str_round_trip() {
        for typ in [JwtTyp::Agent, JwtTyp::Auth, JwtTyp::Resource] {
            assert_eq!(JwtTyp::from_str(typ.as_str()), Ok(typ));
        }
        assert!(JwtTyp::from_str("unknown").is_err());
    }
}
