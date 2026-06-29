use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use ed25519_dalek::{Signature, Verifier, VerifyingKey};
use http::HeaderMap;

use crate::error::{AAuthError, Result};
use crate::jwt::{VerifiedToken, jwk_thumbprint};

/// Result of verifying an incoming HTTP Signature on a request.
#[derive(Debug, Clone)]
pub struct VerifiedSignature {
    pub jwt: String,
    pub thumbprint: String,
}

pub fn build_signature_base(
    method: &str,
    authority: &str,
    path: &str,
    signature_key: &str,
    created: u64,
) -> String {
    format!(
        "\"@method\": {}\n\"@authority\": {}\n\"@path\": {}\n\"signature-key\": {}\n\"@signature-params\": (\"@method\" \"@authority\" \"@path\" \"signature-key\");created={created}",
        method.to_lowercase(),
        authority,
        path,
        signature_key,
    )
}

pub fn parse_signature_key_jwt(headers: &HeaderMap) -> Result<String> {
    let header = header_value(headers, "signature-key")
        .ok_or_else(|| AAuthError::Message("Missing signature-key header".into()))?;
    let start = header
        .find("jwt=\"")
        .ok_or_else(|| AAuthError::Message("signature-key missing jwt parameter".into()))?
        + 5;
    let rest = &header[start..];
    let end = rest
        .find('"')
        .ok_or_else(|| AAuthError::Message("signature-key jwt not quoted".into()))?;
    Ok(rest[..end].to_string())
}

pub fn parse_signature_created(signature_input: &str) -> Result<u64> {
    let created = signature_input
        .split("created=")
        .nth(1)
        .ok_or_else(|| AAuthError::Message("signature-input missing created".into()))?
        .split(';')
        .next()
        .unwrap_or_default()
        .trim();
    created
        .parse()
        .map_err(|e| AAuthError::Message(format!("invalid signature-input created: {e}")))
}

pub fn parse_signature_value(signature: &str) -> Result<Vec<u8>> {
    let value = signature
        .strip_prefix("sig=:")
        .and_then(|rest| rest.strip_suffix(':'))
        .ok_or_else(|| AAuthError::Message("invalid signature header format".into()))?;
    URL_SAFE_NO_PAD
        .decode(value)
        .map_err(|e| AAuthError::Message(e.to_string()))
}

pub fn verify_request_signature(
    method: &str,
    authority: &str,
    path: &str,
    headers: &HeaderMap,
) -> Result<VerifiedSignature> {
    let signature_key = header_value(headers, "signature-key")
        .ok_or_else(|| AAuthError::Message("Missing signature-key header".into()))?
        .to_string();
    let signature_input = header_value(headers, "signature-input")
        .ok_or_else(|| AAuthError::Message("Missing signature-input header".into()))?
        .to_string();
    let signature_header = header_value(headers, "signature")
        .ok_or_else(|| AAuthError::Message("Missing signature header".into()))?
        .to_string();

    let jwt = parse_signature_key_jwt(headers)?;
    let claims = VerifiedToken::decode_unverified(&jwt)?;
    let cnf_jwk = claims.cnf_jwk();
    let thumbprint = jwk_thumbprint(cnf_jwk)?;

    let created = parse_signature_created(&signature_input)?;
    let signature_base = build_signature_base(method, authority, path, &signature_key, created);
    let signature_bytes = parse_signature_value(&signature_header)?;
    let verifying_key = verifying_key_from_jwk(cnf_jwk)?;
    let signature =
        Signature::from_slice(&signature_bytes).map_err(|e| AAuthError::Message(e.to_string()))?;

    verifying_key
        .verify(signature_base.as_bytes(), &signature)
        .map_err(|_| AAuthError::Message("HTTP signature verification failed".into()))?;

    Ok(VerifiedSignature { jwt, thumbprint })
}

fn verifying_key_from_jwk(jwk: &crate::jwt::OkpJwk) -> Result<VerifyingKey> {
    let bytes = URL_SAFE_NO_PAD
        .decode(&jwk.x)
        .map_err(|e| AAuthError::Message(e.to_string()))?;
    let key_bytes: [u8; 32] = bytes
        .try_into()
        .map_err(|_| AAuthError::Message("invalid Ed25519 public key length".into()))?;
    VerifyingKey::from_bytes(&key_bytes).map_err(|e| AAuthError::Message(e.to_string()))
}

fn header_value<'a>(headers: &'a HeaderMap, name: &str) -> Option<&'a str> {
    headers.get(name).and_then(|v| v.to_str().ok()).or_else(|| {
        headers.iter().find_map(|(k, v)| {
            if k.as_str().eq_ignore_ascii_case(name) {
                v.to_str().ok()
            } else {
                None
            }
        })
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn signature_base_includes_components() {
        let base = build_signature_base(
            "GET",
            "resource.example",
            "/api/data",
            "sig=jwt;jwt=\"abc\"",
            1,
        );
        assert!(base.contains("@method"));
        assert!(base.contains("@authority"));
        assert!(base.contains("@path"));
        assert!(base.contains("signature-key"));
    }

    #[test]
    fn parse_signature_key_jwt_from_header() {
        let mut headers = HeaderMap::new();
        headers.insert(
            "signature-key",
            "sig=jwt;jwt=\"eyJhbGciOiJIUzI1NiJ9.test\"".parse().unwrap(),
        );
        let jwt = parse_signature_key_jwt(&headers).unwrap();
        assert_eq!(jwt, "eyJhbGciOiJIUzI1NiJ9.test");
    }
}
