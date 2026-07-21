use std::time::{SystemTime, UNIX_EPOCH};

use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use ed25519_dalek::{Signature, Signer, Verifier, VerifyingKey};
use http::HeaderMap;

use crate::error::{AAuthError, JwtError};
use crate::jwt::{OkpSigningJwk, VerifiedToken, jwk_thumbprint};

pub use crate::error::SignatureError;

const DEFAULT_SIGNATURE_MAX_AGE_SECS: u64 = 60;
const SIGNATURE_CLOCK_SKEW_SECS: i64 = 60;

pub type Result<T> = std::result::Result<T, SignatureError>;

/// Map JWT helper results (`AAuthError`) into [`SignatureError`] while those helpers still
/// return the umbrella type.
fn from_jwt_aauth(err: AAuthError) -> SignatureError {
    match err {
        AAuthError::Jwt(e) => SignatureError::Jwt(e),
        AAuthError::Signature(e) => e,
        AAuthError::Verify(crate::error::VerifyError::Jwt(e)) => SignatureError::Jwt(e),
        other => SignatureError::Jwt(JwtError::UnknownTyp(other.to_string())),
    }
}

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

pub fn build_signature_base(
    method: &str,
    authority: &str,
    path: &str,
    signature_key: &str,
    created: u64,
) -> String {
    build_signature_base_with_extras(method, authority, path, signature_key, created, &[]).0
}

pub fn build_signature_base_with_extras(
    method: &str,
    authority: &str,
    path: &str,
    signature_key: &str,
    created: u64,
    extras: &[(&str, &str)],
) -> (String, String) {
    let mut components = vec![
        "@method".to_string(),
        "@authority".to_string(),
        "@path".to_string(),
        "signature-key".to_string(),
    ];
    for (name, _) in extras {
        components.push((*name).to_string());
    }

    let params = components
        .iter()
        .map(|c| format!("\"{c}\""))
        .collect::<Vec<_>>()
        .join(" ");
    let signature_params = format!("({params});created={created}");

    let mut lines = vec![
        format!("\"@method\": {}", method.to_lowercase()),
        format!("\"@authority\": {authority}"),
        format!("\"@path\": {path}"),
        format!("\"signature-key\": {signature_key}"),
    ];
    for (name, value) in extras {
        lines.push(format!("\"{name}\": {value}"));
    }
    lines.push(format!("\"@signature-params\": {signature_params}"));

    (lines.join("\n"), signature_params)
}

pub fn parse_signature_key_jwt(headers: &HeaderMap) -> Result<String> {
    let header =
        header_value(headers, "signature-key").ok_or(SignatureError::MissingSignatureKey)?;
    let start = header
        .find("jwt=\"")
        .ok_or(SignatureError::MissingJwtParam)?
        + 5;
    let rest = &header[start..];
    let end = rest.find('"').ok_or(SignatureError::JwtNotQuoted)?;
    Ok(rest[..end].to_string())
}

pub fn parse_signature_created(signature_input: &str) -> Result<u64> {
    let created = signature_input
        .split("created=")
        .nth(1)
        .ok_or(SignatureError::MissingCreated)?
        .split(';')
        .next()
        .unwrap_or_default()
        .trim();
    created.parse().map_err(SignatureError::InvalidCreated)
}

pub fn parse_covered_components(signature_input: &str) -> Result<Vec<String>> {
    let start = signature_input
        .find('(')
        .ok_or(SignatureError::MissingCoveredComponents)?;
    let end = signature_input
        .find(')')
        .ok_or(SignatureError::MissingCoveredComponents)?;
    let inner = &signature_input[start + 1..end];
    Ok(inner
        .split_whitespace()
        .map(|c| c.trim_matches('"').to_string())
        .filter(|c| !c.is_empty())
        .collect())
}

pub fn parse_signature_value(signature: &str) -> Result<Vec<u8>> {
    let value = signature
        .strip_prefix("sig=:")
        .and_then(|rest| rest.strip_suffix(':'))
        .ok_or(SignatureError::InvalidSignatureFormat)?;
    URL_SAFE_NO_PAD
        .decode(value)
        .map_err(SignatureError::InvalidEncoding)
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
    let signature_key = header_value(headers, "signature-key")
        .ok_or(SignatureError::MissingSignatureKey)?
        .to_string();
    let signature_input = header_value(headers, "signature-input")
        .ok_or(SignatureError::MissingSignatureInput)?
        .to_string();
    let signature_header = header_value(headers, "signature")
        .ok_or(SignatureError::MissingSignature)?
        .to_string();

    let covered = parse_covered_components(&signature_input)?;
    for required in ["@method", "@authority", "@path", "signature-key"] {
        if !covered.iter().any(|c| c == required) {
            return Err(SignatureError::MissingComponent(required));
        }
    }
    if options.require_authorization && !covered.iter().any(|c| c == "authorization") {
        return Err(SignatureError::MissingAuthorizationComponent);
    }

    let jwt = parse_signature_key_jwt(headers)?;
    let claims = VerifiedToken::decode_unverified(&jwt).map_err(from_jwt_aauth)?;
    let cnf_jwk = claims.cnf_jwk();
    let thumbprint = jwk_thumbprint(cnf_jwk).map_err(from_jwt_aauth)?;

    let created = parse_signature_created(&signature_input)?;
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs();
    if created > now + options.clock_skew_secs as u64 {
        return Err(SignatureError::CreatedInFuture);
    }
    if now.saturating_sub(created) > options.max_age_secs + options.clock_skew_secs as u64 {
        return Err(SignatureError::Expired);
    }

    let mut extras = Vec::new();
    if covered.iter().any(|c| c == "authorization") {
        let authorization = header_value(headers, "authorization")
            .ok_or(SignatureError::AuthorizationHeaderMissing)?;
        extras.push(("authorization", authorization));
    }

    let (signature_base, _) =
        build_signature_base_with_extras(method, authority, path, &signature_key, created, &extras);
    let signature_bytes = parse_signature_value(&signature_header)?;
    let verifying_key = verifying_key_from_jwk(cnf_jwk)?;
    let signature = Signature::from_slice(&signature_bytes)
        .map_err(SignatureError::InvalidSignatureBytes)?;

    verifying_key
        .verify(signature_base.as_bytes(), &signature)
        .map_err(|_| SignatureError::VerificationFailed)?;

    Ok(VerifiedSignature { jwt, thumbprint })
}

/// Apply HTTP Message Signature headers to an outbound request (server-side federation, etc.).
pub fn apply_outbound_signature(
    headers: &mut HeaderMap,
    method: &str,
    authority: &str,
    path: &str,
    signature_key_jwt: &str,
    signing_jwk: &OkpSigningJwk,
    authorization: Option<&str>,
) -> Result<()> {
    let signature_key = format!("sig=jwt;jwt=\"{signature_key_jwt}\"");

    let mut extras = Vec::new();
    if let Some(auth) = authorization {
        extras.push(("authorization", auth));
    }

    let created = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs();

    let (signature_base, signature_params) =
        build_signature_base_with_extras(method, authority, path, &signature_key, created, &extras);

    let signing_key = signing_key_from_jwk(signing_jwk)?;
    let signature_bytes = signing_key.sign(signature_base.as_bytes());
    let signature = URL_SAFE_NO_PAD.encode(signature_bytes.to_bytes());

    let mut components = vec![
        "\"@method\"".to_string(),
        "\"@authority\"".to_string(),
        "\"@path\"".to_string(),
        "\"signature-key\"".to_string(),
    ];
    if authorization.is_some() {
        components.push("\"authorization\"".to_string());
    }
    let signature_input = format!("sig=({});created={created}", components.join(" "));

    headers.insert(
        http::HeaderName::from_static("signature-key"),
        http::HeaderValue::from_str(&signature_key)
            .map_err(SignatureError::InvalidHeaderValue)?,
    );
    headers.insert(
        http::HeaderName::from_static("signature-input"),
        http::HeaderValue::from_str(&signature_input)
            .map_err(SignatureError::InvalidHeaderValue)?,
    );
    headers.insert(
        http::HeaderName::from_static("signature"),
        http::HeaderValue::from_str(&format!("sig=:{signature}:"))
            .map_err(SignatureError::InvalidHeaderValue)?,
    );

    let _ = signature_params;
    Ok(())
}

pub fn signing_key_from_jwk(jwk: &OkpSigningJwk) -> Result<ed25519_dalek::SigningKey> {
    let bytes = URL_SAFE_NO_PAD
        .decode(&jwk.d)
        .map_err(SignatureError::InvalidEncoding)?;
    let key_bytes: [u8; 32] = bytes
        .try_into()
        .map_err(|_| SignatureError::InvalidKeyLength)?;
    Ok(ed25519_dalek::SigningKey::from_bytes(&key_bytes))
}

fn verifying_key_from_jwk(jwk: &crate::jwt::OkpJwk) -> Result<VerifyingKey> {
    let bytes = URL_SAFE_NO_PAD
        .decode(&jwk.x)
        .map_err(SignatureError::InvalidEncoding)?;
    let key_bytes: [u8; 32] = bytes
        .try_into()
        .map_err(|_| SignatureError::InvalidKeyLength)?;
    VerifyingKey::from_bytes(&key_bytes).map_err(SignatureError::InvalidVerifyingKey)
}

pub(crate) fn header_value<'a>(headers: &'a HeaderMap, name: &str) -> Option<&'a str> {
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

    #[test]
    fn stale_signature_rejected() {
        use crate::{create_test_keys, mint_agent_jwt};

        let keys = create_test_keys();
        let agent_url = "http://127.0.0.1";
        let agent_jwt = mint_agent_jwt(&keys, agent_url, "aauth:test@example.com", None);
        let signature_key = format!("sig=jwt;jwt=\"{agent_jwt}\"");
        let created = 1u64;
        let signature_base =
            build_signature_base("GET", "127.0.0.1", "/api/data", &signature_key, created);
        let signing_key = signing_key_from_jwk(&keys.agent_ephemeral.signing_jwk()).unwrap();
        let sig = URL_SAFE_NO_PAD.encode(signing_key.sign(signature_base.as_bytes()).to_bytes());

        let mut headers = HeaderMap::new();
        headers.insert("signature-key", signature_key.parse().unwrap());
        headers.insert(
            "signature-input",
            format!(
                "sig=(\"@method\" \"@authority\" \"@path\" \"signature-key\");created={created}"
            )
            .parse()
            .unwrap(),
        );
        headers.insert("signature", format!("sig=:{sig}:").parse().unwrap());

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
}
