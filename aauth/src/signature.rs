use std::time::{SystemTime, UNIX_EPOCH};

use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use ed25519_dalek::{Signature, Signer, Verifier, VerifyingKey};
use http::HeaderMap;

use crate::error::{AAuthError, Result};
use crate::jwt::{OkpSigningJwk, VerifiedToken, jwk_thumbprint};

const DEFAULT_SIGNATURE_MAX_AGE_SECS: u64 = 60;
const SIGNATURE_CLOCK_SKEW_SECS: i64 = 60;

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

pub fn parse_covered_components(signature_input: &str) -> Result<Vec<String>> {
    let start = signature_input
        .find('(')
        .ok_or_else(|| AAuthError::Message("signature-input missing covered components".into()))?;
    let end = signature_input
        .find(')')
        .ok_or_else(|| AAuthError::Message("signature-input missing covered components".into()))?;
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
        .ok_or_else(|| AAuthError::Message("Missing signature-key header".into()))?
        .to_string();
    let signature_input = header_value(headers, "signature-input")
        .ok_or_else(|| AAuthError::Message("Missing signature-input header".into()))?
        .to_string();
    let signature_header = header_value(headers, "signature")
        .ok_or_else(|| AAuthError::Message("Missing signature header".into()))?
        .to_string();

    let covered = parse_covered_components(&signature_input)?;
    for required in ["@method", "@authority", "@path", "signature-key"] {
        if !covered.iter().any(|c| c == required) {
            return Err(AAuthError::Message(format!(
                "signature-input missing required component: {required}"
            )));
        }
    }
    if options.require_authorization && !covered.iter().any(|c| c == "authorization") {
        return Err(AAuthError::Message(
            "signature-input missing required authorization component".into(),
        ));
    }

    let jwt = parse_signature_key_jwt(headers)?;
    let claims = VerifiedToken::decode_unverified(&jwt)?;
    let cnf_jwk = claims.cnf_jwk();
    let thumbprint = jwk_thumbprint(cnf_jwk)?;

    let created = parse_signature_created(&signature_input)?;
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs();
    if created > now + options.clock_skew_secs as u64 {
        return Err(AAuthError::Message(
            "signature created in the future".into(),
        ));
    }
    if now.saturating_sub(created) > options.max_age_secs + options.clock_skew_secs as u64 {
        return Err(AAuthError::Message("signature expired".into()));
    }

    let mut extras = Vec::new();
    if covered.iter().any(|c| c == "authorization") {
        let authorization = header_value(headers, "authorization").ok_or_else(|| {
            AAuthError::Message("authorization covered but Authorization header missing".into())
        })?;
        extras.push(("authorization", authorization));
    }

    let (signature_base, _) =
        build_signature_base_with_extras(method, authority, path, &signature_key, created, &extras);
    let signature_bytes = parse_signature_value(&signature_header)?;
    let verifying_key = verifying_key_from_jwk(cnf_jwk)?;
    let signature =
        Signature::from_slice(&signature_bytes).map_err(|e| AAuthError::Message(e.to_string()))?;

    verifying_key
        .verify(signature_base.as_bytes(), &signature)
        .map_err(|_| AAuthError::Message("HTTP signature verification failed".into()))?;

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
            .map_err(|e| AAuthError::Message(e.to_string()))?,
    );
    headers.insert(
        http::HeaderName::from_static("signature-input"),
        http::HeaderValue::from_str(&signature_input)
            .map_err(|e| AAuthError::Message(e.to_string()))?,
    );
    headers.insert(
        http::HeaderName::from_static("signature"),
        http::HeaderValue::from_str(&format!("sig=:{signature}:"))
            .map_err(|e| AAuthError::Message(e.to_string()))?,
    );

    let _ = signature_params;
    Ok(())
}

pub(crate) fn signing_key_from_jwk(jwk: &OkpSigningJwk) -> Result<ed25519_dalek::SigningKey> {
    let bytes = URL_SAFE_NO_PAD
        .decode(&jwk.d)
        .map_err(|e| AAuthError::Message(e.to_string()))?;
    let key_bytes: [u8; 32] = bytes
        .try_into()
        .map_err(|_| AAuthError::Message("invalid Ed25519 private key length".into()))?;
    Ok(ed25519_dalek::SigningKey::from_bytes(&key_bytes))
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
        assert!(err.to_string().contains("signature expired"));
    }

    #[cfg(feature = "agent-reqwest")]
    #[tokio::test]
    async fn sign_request_verify_roundtrip() {
        use crate::agent::reqwest::signed::sign_request;
        use crate::{create_key_provider, create_test_keys, mint_agent_jwt};

        let keys = create_test_keys();
        let agent_url = "http://127.0.0.1";
        let agent_jwt = mint_agent_jwt(&keys, agent_url, "aauth:test@example.com", None);
        let provider = create_key_provider(&keys, agent_jwt);
        let material = provider.key_material().await.unwrap();

        let url = format!("{agent_url}/api/data");
        let mut req = reqwest::Client::new().get(&url).build().unwrap();
        sign_request(&mut req, &material).unwrap();

        let headers = req.headers().clone();
        let verified = verify_request_signature(
            req.method().as_str(),
            req.url().authority(),
            req.url().path(),
            &headers,
        )
        .unwrap();

        assert_eq!(verified.thumbprint, keys.agent_ephemeral.thumbprint());
    }
}
