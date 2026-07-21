mod claims;
mod decode;
#[cfg(any(feature = "person-server", feature = "access-server"))]
mod mint;

pub use claims::{
    ActClaim, AgentClaims, AuthClaims, CnfClaim, ParsedToken, PublicJwk, ResourceClaims,
    ResourceInteractionClaim, SigningJwk,
};
pub use decode::{JwtHeaderParts, jwt_header, verified_validation, verified_validation_for_jwt};
#[cfg(any(feature = "person-server", feature = "access-server"))]
pub(crate) use mint::{AuthJwtMintParams, encode_auth_jwt};

use jsonwebtoken::jwk::JwkSet;

use crate::error::{JwtError, Result};
use crate::protocol::JwtTyp;

impl JwtTyp {
    /// Reads and parses the JWT `typ` header.
    pub fn from_jwt(jwt: &str) -> Result<Self> {
        Ok(jwt_header(jwt)?.typ)
    }
}

/// RFC 7638 JWK thumbprint (delegates to [`httpsig_key::jwk_thumbprint`]).
pub fn jwk_thumbprint(jwk: &PublicJwk) -> Result<String> {
    httpsig_key::jwk_thumbprint(jwk).map_err(|e| match e {
        httpsig_key::Error::UnsupportedSigningJwk { kty, .. } => {
            JwtError::UnsupportedKty(kty).into()
        }
        other => JwtError::Thumbprint(other.to_string()).into(),
    })
}

pub fn jwk_set_from_public(keys: &[PublicJwk]) -> Result<JwkSet> {
    let mut jwt_keys = Vec::with_capacity(keys.len());
    for key in keys {
        let jwk: jsonwebtoken::jwk::Jwk =
            serde_json::from_value(serde_json::to_value(key).map_err(JwtError::Canonicalize)?)
                .map_err(JwtError::JwkSet)?;
        jwt_keys.push(jwk);
    }
    Ok(JwkSet { keys: jwt_keys })
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::str::FromStr;

    #[test]
    fn thumbprint_is_stable() {
        let jwk = PublicJwk {
            kty: "OKP".into(),
            crv: "Ed25519".into(),
            x: "11qYAYKxCrfVS_7TyWQHOg7hcvPapiMlrwIaaPcHURo".into(),
            y: None,
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
