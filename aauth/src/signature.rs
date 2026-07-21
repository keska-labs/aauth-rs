use std::time::{SystemTime, UNIX_EPOCH};

use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use ed25519_dalek::{
    Signature as Ed25519Signature, Signer as Ed25519Signer, Verifier as Ed25519Verifier,
    VerifyingKey as Ed25519VerifyingKey,
};
use http::HeaderMap;
use http::header::{AUTHORIZATION, HeaderName};
use p256::ecdsa::signature::{Signer as Es256Signer, Verifier as Es256Verifier};
use p256::ecdsa::{
    Signature as Es256Signature, SigningKey as Es256SigningKey, VerifyingKey as Es256VerifyingKey,
};
use p256::elliptic_curve::sec1::FromEncodedPoint;
use p256::{EncodedPoint, SecretKey as P256SecretKey};

use crate::error::{AAuthError, JwtError};
use crate::jwt::{OkpSigningJwk, VerifiedToken, jwk_thumbprint};
use crate::protocol::{SIGNATURE, SIGNATURE_INPUT, SIGNATURE_KEY, SIGNATURE_KEY_NAME};

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
        SIGNATURE_KEY_NAME.to_string(),
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
        format!("\"@method\": {}", method.to_uppercase()),
        format!("\"@authority\": {authority}"),
        format!("\"@path\": {path}"),
        format!("\"{SIGNATURE_KEY_NAME}\": {signature_key}"),
    ];
    for (name, value) in extras {
        lines.push(format!("\"{name}\": {value}"));
    }
    lines.push(format!("\"@signature-params\": {signature_params}"));

    (lines.join("\n"), signature_params)
}

fn parse_signature_key_jwt(headers: &HeaderMap) -> Result<String> {
    let header =
        header_value(headers, &SIGNATURE_KEY).ok_or(SignatureError::MissingSignatureKey)?;
    let start = header
        .find("jwt=\"")
        .ok_or(SignatureError::MissingJwtParam)?
        + 5;
    let rest = &header[start..];
    let end = rest.find('"').ok_or(SignatureError::JwtNotQuoted)?;
    Ok(rest[..end].to_string())
}

fn parse_signature_created(signature_input: &str) -> Result<u64> {
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

fn parse_covered_components(signature_input: &str) -> Result<Vec<String>> {
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

fn parse_signature_value(signature: &str) -> Result<Vec<u8>> {
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
    let signature_key = header_value(headers, &SIGNATURE_KEY)
        .ok_or(SignatureError::MissingSignatureKey)?
        .to_string();
    let signature_input = header_value(headers, &SIGNATURE_INPUT)
        .ok_or(SignatureError::MissingSignatureInput)?
        .to_string();
    let signature_header = header_value(headers, &SIGNATURE)
        .ok_or(SignatureError::MissingSignature)?
        .to_string();

    let covered = parse_covered_components(&signature_input)?;
    for required in ["@method", "@authority", "@path", SIGNATURE_KEY_NAME] {
        if !covered.iter().any(|c| c == required) {
            return Err(SignatureError::MissingComponent(required));
        }
    }
    if options.require_authorization && !covered.iter().any(|c| c == AUTHORIZATION.as_str()) {
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
    if covered.iter().any(|c| c == AUTHORIZATION.as_str()) {
        let authorization = header_value(headers, &AUTHORIZATION)
            .ok_or(SignatureError::AuthorizationHeaderMissing)?;
        extras.push((AUTHORIZATION.as_str(), authorization));
    }

    let (signature_base, _) =
        build_signature_base_with_extras(method, authority, path, &signature_key, created, &extras);
    let signature_bytes = parse_signature_value(&signature_header)?;
    verify_signature(cnf_jwk, signature_base.as_bytes(), &signature_bytes)?;

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
        extras.push((AUTHORIZATION.as_str(), auth));
    }

    let created = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs();

    let (signature_base, signature_params) =
        build_signature_base_with_extras(method, authority, path, &signature_key, created, &extras);

    let signature =
        URL_SAFE_NO_PAD.encode(sign_http_message(signing_jwk, signature_base.as_bytes())?);

    let mut components = vec![
        "\"@method\"".to_string(),
        "\"@authority\"".to_string(),
        "\"@path\"".to_string(),
        format!("\"{SIGNATURE_KEY_NAME}\""),
    ];
    if authorization.is_some() {
        components.push(format!("\"{}\"", AUTHORIZATION.as_str()));
    }
    let signature_input = format!("sig=({});created={created}", components.join(" "));

    headers.insert(
        SIGNATURE_KEY,
        http::HeaderValue::from_str(&signature_key).map_err(SignatureError::InvalidHeaderValue)?,
    );
    headers.insert(
        SIGNATURE_INPUT,
        http::HeaderValue::from_str(&signature_input)
            .map_err(SignatureError::InvalidHeaderValue)?,
    );
    headers.insert(
        SIGNATURE,
        http::HeaderValue::from_str(&format!("sig=:{signature}:"))
            .map_err(SignatureError::InvalidHeaderValue)?,
    );

    let _ = signature_params;
    Ok(())
}

/// Sign an HTTP Message Signature base string with an Ed25519 or ES256 (P-256) JWK.
pub fn sign_http_message(jwk: &OkpSigningJwk, message: &[u8]) -> Result<Vec<u8>> {
    match (jwk.kty.as_str(), jwk.crv.as_str()) {
        ("OKP", "Ed25519") => {
            let signing_key = signing_key_from_jwk(jwk)?;
            Ok(Ed25519Signer::sign(&signing_key, message)
                .to_bytes()
                .to_vec())
        }
        ("EC", "P-256") => {
            let signing_key = es256_signing_key_from_jwk(jwk)?;
            let signature: Es256Signature = signing_key.sign(message);
            Ok(signature.to_bytes().to_vec())
        }
        _ => Err(SignatureError::UnsupportedSigningJwk {
            kty: jwk.kty.clone(),
            crv: jwk.crv.clone(),
        }),
    }
}

/// Decode an Ed25519 private key from a JWK (`kty=OKP`, `crv=Ed25519`).
pub fn signing_key_from_jwk(jwk: &OkpSigningJwk) -> Result<ed25519_dalek::SigningKey> {
    if jwk.kty != "OKP" || jwk.crv != "Ed25519" {
        return Err(SignatureError::UnsupportedSigningJwk {
            kty: jwk.kty.clone(),
            crv: jwk.crv.clone(),
        });
    }
    let bytes = URL_SAFE_NO_PAD
        .decode(&jwk.d)
        .map_err(SignatureError::InvalidEncoding)?;
    let key_bytes: [u8; 32] = bytes
        .try_into()
        .map_err(|_| SignatureError::InvalidKeyLength)?;
    Ok(ed25519_dalek::SigningKey::from_bytes(&key_bytes))
}

fn es256_signing_key_from_jwk(jwk: &OkpSigningJwk) -> Result<Es256SigningKey> {
    let bytes = URL_SAFE_NO_PAD
        .decode(&jwk.d)
        .map_err(SignatureError::InvalidEncoding)?;
    let secret = P256SecretKey::from_slice(&bytes)
        .map_err(|e| SignatureError::InvalidEs256Key(e.to_string()))?;
    Ok(Es256SigningKey::from(secret))
}

fn verify_signature(jwk: &crate::jwt::OkpJwk, message: &[u8], signature: &[u8]) -> Result<()> {
    match (jwk.kty.as_str(), jwk.crv.as_str()) {
        ("OKP", "Ed25519") => {
            let verifying_key = ed25519_verifying_key_from_jwk(jwk)?;
            let signature = Ed25519Signature::from_slice(signature)
                .map_err(SignatureError::InvalidSignatureBytes)?;
            verifying_key
                .verify(message, &signature)
                .map_err(|_| SignatureError::VerificationFailed)
        }
        ("EC", "P-256") => {
            let verifying_key = es256_verifying_key_from_jwk(jwk)?;
            let signature = Es256Signature::from_slice(signature)
                .map_err(|e| SignatureError::InvalidEs256Key(e.to_string()))?;
            verifying_key
                .verify(message, &signature)
                .map_err(|_| SignatureError::VerificationFailed)
        }
        _ => Err(SignatureError::UnsupportedSigningJwk {
            kty: jwk.kty.clone(),
            crv: jwk.crv.clone(),
        }),
    }
}

fn ed25519_verifying_key_from_jwk(jwk: &crate::jwt::OkpJwk) -> Result<Ed25519VerifyingKey> {
    let bytes = URL_SAFE_NO_PAD
        .decode(&jwk.x)
        .map_err(SignatureError::InvalidEncoding)?;
    let key_bytes: [u8; 32] = bytes
        .try_into()
        .map_err(|_| SignatureError::InvalidKeyLength)?;
    Ed25519VerifyingKey::from_bytes(&key_bytes).map_err(SignatureError::InvalidVerifyingKey)
}

fn es256_verifying_key_from_jwk(jwk: &crate::jwt::OkpJwk) -> Result<Es256VerifyingKey> {
    let y = jwk.y.as_deref().ok_or(SignatureError::MissingEcY)?;
    let x = URL_SAFE_NO_PAD
        .decode(&jwk.x)
        .map_err(SignatureError::InvalidEncoding)?;
    let y = URL_SAFE_NO_PAD
        .decode(y)
        .map_err(SignatureError::InvalidEncoding)?;
    let x: [u8; 32] = x
        .as_slice()
        .try_into()
        .map_err(|_| SignatureError::InvalidKeyLength)?;
    let y: [u8; 32] = y
        .as_slice()
        .try_into()
        .map_err(|_| SignatureError::InvalidKeyLength)?;
    let point = EncodedPoint::from_affine_coordinates(&x.into(), &y.into(), false);
    let option = p256::PublicKey::from_encoded_point(&point);
    let public = option
        .into_option()
        .ok_or_else(|| SignatureError::InvalidEs256Key("invalid P-256 public point".into()))?;
    Ok(Es256VerifyingKey::from(public))
}

pub(crate) fn header_value<'a>(headers: &'a HeaderMap, name: &HeaderName) -> Option<&'a str> {
    headers.get(name).and_then(|v| v.to_str().ok())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn signature_base_includes_components() {
        let base = build_signature_base_with_extras(
            "GET",
            "resource.example",
            "/api/data",
            "sig=jwt;jwt=\"abc\"",
            1,
            &[],
        )
        .0;
        assert!(base.contains("@method"));
        assert!(base.contains("@authority"));
        assert!(base.contains("@path"));
        assert!(base.contains(SIGNATURE_KEY_NAME));
    }

    #[test]
    fn parse_signature_key_jwt_from_header() {
        let mut headers = HeaderMap::new();
        headers.insert(
            SIGNATURE_KEY,
            "sig=jwt;jwt=\"eyJhbGciOiJIUzI1NiJ9.test\"".parse().unwrap(),
        );
        let jwt = parse_signature_key_jwt(&headers).unwrap();
        assert_eq!(jwt, "eyJhbGciOiJIUzI1NiJ9.test");
    }

    #[test]
    fn stale_signature_rejected() {
        use crate::TestKeys;

        let keys = TestKeys::generate();
        let agent_url = "http://127.0.0.1";
        let agent_jwt = keys.mint_agent_jwt(agent_url, "aauth:test@example.com", None);
        let signature_key = format!("sig=jwt;jwt=\"{agent_jwt}\"");
        let created = 1u64;
        let signature_base = build_signature_base_with_extras(
            "GET",
            "127.0.0.1",
            "/api/data",
            &signature_key,
            created,
            &[],
        )
        .0;
        let sig = URL_SAFE_NO_PAD.encode(
            sign_http_message(
                &keys.agent_ephemeral.signing_jwk(),
                signature_base.as_bytes(),
            )
            .unwrap(),
        );

        let mut headers = HeaderMap::new();
        headers.insert(SIGNATURE_KEY, signature_key.parse().unwrap());
        headers.insert(
            SIGNATURE_INPUT,
            format!(
                "sig=(\"@method\" \"@authority\" \"@path\" \"{SIGNATURE_KEY_NAME}\");created={created}"
            )
            .parse()
            .unwrap(),
        );
        headers.insert(SIGNATURE, format!("sig=:{sig}:").parse().unwrap());

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
