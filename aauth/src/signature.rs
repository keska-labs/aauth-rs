//! HTTP Message Signature helpers for AAuth (agent JWT via Signature-Key).
//!
//! Crypto and Signature-Key wire handling live in [`httpsig_key`]. This module
//! keeps AAuth-facing types (`VerifiedSignature`, JWT required) and error mapping.
//!
//! Spec: `draft-hardt-httpbis-signature-key-05.txt` §3; AAuth uses `scheme=jwt`.
//! AAuth profile: `draft-hardt-oauth-aauth-protocol.md#http-message-signatures-profile`,
//! `#verification`, `#keying-material`.

use http::HeaderMap;
use http::header::AUTHORIZATION;
use httpsig_key::protocol::{
    SignatureKey as HttpsigSignatureKey, SignatureKeyJwt as HttpsigSignatureKeyJwt, SigningMaterial,
};
use httpsig_key::{SignOptions, VerifyOptions, sign as httpsig_sign, verify as httpsig_verify};

use crate::jwt::SigningJwk;
use crate::protocol::{KeyMaterial, SignatureKey};

pub use crate::error::SignatureError;

const DEFAULT_SIGNATURE_MAX_AGE_SECS: u64 = 60;
const SIGNATURE_CLOCK_SKEW_SECS: i64 = 60;

pub type Result<T> = std::result::Result<T, SignatureError>;

/// Result of verifying an incoming HTTP Signature on a request.
#[derive(Debug, Clone)]
pub struct VerifiedSignature {
    pub jwt: String,
    pub thumbprint: String,
}

#[derive(Debug, Clone)]
pub struct SignatureVerifyOptions {
    pub max_age_secs: u64,
    pub clock_skew_secs: i64,
    pub require_authorization: bool,
}

impl Default for SignatureVerifyOptions {
    fn default() -> Self {
        Self {
            max_age_secs: DEFAULT_SIGNATURE_MAX_AGE_SECS,
            clock_skew_secs: SIGNATURE_CLOCK_SKEW_SECS,
            require_authorization: false,
        }
    }
}

fn signing_material(material: &KeyMaterial) -> Result<SigningMaterial> {
    let jwt = match &material.signature_key {
        SignatureKey::Jwt(j) => j.jwt.clone(),
        SignatureKey::JktJwt(j) => j.jwt.clone(),
        SignatureKey::Hwk(_) => return Err(SignatureError::HwkUnsupported),
    };
    Ok(SigningMaterial {
        signing_jwk: material.signing_jwk.clone(),
        signature_key: HttpsigSignatureKey::Jwt(HttpsigSignatureKeyJwt { jwt }),
    })
}

fn map_httpsig_error(err: httpsig_key::Error) -> SignatureError {
    match err {
        httpsig_key::Error::MissingSignatureKey => SignatureError::MissingSignatureKey,
        httpsig_key::Error::MissingJwtParam => SignatureError::MissingJwtParam,
        httpsig_key::Error::MissingSignatureInput => SignatureError::MissingSignatureInput,
        httpsig_key::Error::MissingSignature => SignatureError::MissingSignature,
        httpsig_key::Error::MissingComponent("authorization") => {
            SignatureError::MissingAuthorizationComponent
        }
        httpsig_key::Error::MissingComponent(c) => SignatureError::MissingComponent(c),
        httpsig_key::Error::AuthorizationHeaderMissing => {
            SignatureError::AuthorizationHeaderMissing
        }
        httpsig_key::Error::CreatedInFuture => SignatureError::CreatedInFuture,
        httpsig_key::Error::Expired => SignatureError::Expired,
        httpsig_key::Error::MissingCreated => SignatureError::MissingCreated,
        httpsig_key::Error::InvalidCreated(e) => SignatureError::InvalidCreated(e),
        httpsig_key::Error::InvalidSignatureFormat => SignatureError::InvalidSignatureFormat,
        httpsig_key::Error::InvalidEncoding(e) => SignatureError::InvalidEncoding(e),
        httpsig_key::Error::InvalidKeyLength => SignatureError::InvalidKeyLength,
        httpsig_key::Error::UnsupportedSigningJwk { kty, crv } => {
            SignatureError::UnsupportedSigningJwk { kty, crv }
        }
        httpsig_key::Error::MissingEcY => SignatureError::MissingEcY,
        httpsig_key::Error::VerificationFailed => SignatureError::VerificationFailed,
        httpsig_key::Error::UnsupportedScheme(s) if s == "hwk" => SignatureError::HwkUnsupported,
        httpsig_key::Error::InvalidHeaderValue(e) => SignatureError::InvalidHeaderValue(e),
        httpsig_key::Error::MissingCoveredComponents => SignatureError::MissingCoveredComponents,
        other => SignatureError::HttpsigKey(other.to_string()),
    }
}

pub fn verify_request_signature(
    method: &str,
    authority: &str,
    path: &str,
    headers: &HeaderMap,
) -> Result<VerifiedSignature> {
    verify_request_signature_with_options(
        method,
        authority,
        path,
        headers,
        &SignatureVerifyOptions::default(),
    )
}

pub fn verify_request_signature_with_options(
    method: &str,
    authority: &str,
    path: &str,
    headers: &HeaderMap,
    options: &SignatureVerifyOptions,
) -> Result<VerifiedSignature> {
    let verified = httpsig_verify(
        method,
        authority,
        path,
        headers,
        &VerifyOptions {
            max_age_secs: options.max_age_secs,
            clock_skew_secs: options.clock_skew_secs,
            require_authorization: options.require_authorization,
            label: None,
        },
    )
    .map_err(map_httpsig_error)?;

    let jwt = verified.jwt.ok_or(SignatureError::MissingJwtParam)?;
    Ok(VerifiedSignature {
        jwt,
        thumbprint: verified.thumbprint,
    })
}

/// Sign `headers` in place with [`KeyMaterial`] (`scheme=jwt`).
pub fn sign_request_headers(
    headers: &mut HeaderMap,
    method: &str,
    authority: &str,
    path: &str,
    material: &KeyMaterial,
    authorization: Option<&str>,
) -> Result<()> {
    let signing = signing_material(material)?;
    let mut options = SignOptions::default();
    if let Some(auth) = authorization {
        options
            .extras
            .push((AUTHORIZATION.as_str().to_string(), auth.to_string()));
    }
    httpsig_sign(headers, method, authority, path, &signing, &options).map_err(map_httpsig_error)
}

/// Apply HTTP Message Signature headers to an outbound request (server-side federation, etc.).
pub fn apply_outbound_signature(
    headers: &mut HeaderMap,
    method: &str,
    authority: &str,
    path: &str,
    signature_key_jwt: &str,
    signing_jwk: &SigningJwk,
    authorization: Option<&str>,
) -> Result<()> {
    let material = KeyMaterial {
        signing_jwk: signing_jwk.clone(),
        signature_key: SignatureKey::Jwt(crate::protocol::SignatureKeyJwt {
            jwt: signature_key_jwt.to_string(),
        }),
    };
    sign_request_headers(headers, method, authority, path, &material, authorization)
}

#[cfg(test)]
mod tests {
    use super::*;
    use httpsig_key::protocol::SIGNATURE_INPUT;

    #[test]
    fn stale_signature_rejected() {
        use crate::TestKeys;

        let keys = TestKeys::generate();
        let agent_url = "http://127.0.0.1";
        let agent_jwt = keys.mint_agent_jwt(agent_url, "aauth:test@example.com", None);
        let material = KeyMaterial {
            signing_jwk: keys.agent_ephemeral.signing_jwk(),
            signature_key: SignatureKey::Jwt(crate::protocol::SignatureKeyJwt { jwt: agent_jwt }),
        };

        let mut headers = HeaderMap::new();
        sign_request_headers(
            &mut headers,
            "GET",
            "127.0.0.1",
            "/api/data",
            &material,
            None,
        )
        .unwrap();

        let input = headers.get(&SIGNATURE_INPUT).unwrap().to_str().unwrap();
        let rewritten = rewrite_created(input, 1);
        headers.insert(SIGNATURE_INPUT, rewritten.parse().unwrap());

        let err = verify_request_signature_with_options(
            "GET",
            "127.0.0.1",
            "/api/data",
            &headers,
            &SignatureVerifyOptions::default(),
        )
        .unwrap_err();
        assert!(matches!(err, SignatureError::Expired));
        assert!(err.to_string().contains("signature expired"));
    }

    fn rewrite_created(signature_input: &str, created: u64) -> String {
        let mut out = String::new();
        let mut parts = signature_input.split(';');
        if let Some(first) = parts.next() {
            out.push_str(first);
        }
        let mut saw_created = false;
        for part in parts {
            out.push(';');
            if part.trim().starts_with("created=") {
                out.push_str(&format!("created={created}"));
                saw_created = true;
            } else {
                out.push_str(part);
            }
        }
        assert!(saw_created, "created param missing in {signature_input}");
        out
    }
}
