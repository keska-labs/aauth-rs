//! Shared auth JWT minting used by Person and Access servers.

use jsonwebtoken::{Algorithm, EncodingKey, Header, encode};
use uuid::Uuid;

use crate::jwt::{AuthClaims, CnfClaim, OkpJwk};
use crate::protocol::JwtTyp;

pub(crate) struct AuthJwtMintParams<'a> {
    pub encoding_key: &'a EncodingKey,
    pub kid: Option<&'a str>,
    pub dwk: &'a str,
    pub iss: &'a str,
    pub aud: &'a str,
    pub agent: &'a str,
    pub agent_jwk: OkpJwk,
    pub sub: Option<&'a str>,
    pub scope: Option<&'a str>,
}

pub(crate) fn encode_auth_jwt(params: AuthJwtMintParams<'_>) -> String {
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs() as i64;

    let claims = AuthClaims {
        iss: params.iss.into(),
        dwk: params.dwk.into(),
        aud: params.aud.into(),
        jti: Uuid::new_v4().to_string(),
        agent: params.agent.into(),
        act: None,
        cnf: CnfClaim {
            jwk: params.agent_jwk,
        },
        iat: now,
        exp: now + 3600,
        sub: params.sub.map(str::to_string),
        scope: params.scope.map(str::to_string),
        tenant: None,
        mission: None,
    };

    let mut header = Header::new(Algorithm::EdDSA);
    header.typ = Some(JwtTyp::Auth.as_str().into());
    header.kid = params.kid.map(str::to_string);

    encode(&header, &claims, params.encoding_key).expect("sign auth jwt")
}
