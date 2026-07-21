//! Verify HTTP Message Signatures that use Signature-Key.
//!
//! Spec: `draft-hardt-httpbis-signature-key-05.txt` §3 (esp. §3.6 verification steps 8–9).
//! AAuth profile: `draft-hardt-oauth-aauth-protocol.md#http-message-signatures-profile`,
//! `#verification`, `#freshness-and-replay` (`created` window; `expires` not yet honored).
//! JWT issuer JWKS verification is left to the application.

use std::time::{SystemTime, UNIX_EPOCH};

use http::HeaderMap;
use http::header::{AUTHORIZATION, HeaderName};
use httpsig::prelude::{
    HttpSignatureBase, HttpSignatureHeaders, message_component::HttpMessageComponent,
};
use serde::Deserialize;

use crate::crypto::public_key_from_jwk;
use crate::error::{Error, Result};
use crate::protocol::{
    PublicJwk, SIGNATURE, SIGNATURE_INPUT, SIGNATURE_KEY, SIGNATURE_KEY_NAME, SignatureKey,
};
use crate::thumbprint::jwk_thumbprint;

const DEFAULT_MAX_AGE_SECS: u64 = 60;
const DEFAULT_CLOCK_SKEW_SECS: i64 = 60;
const DEFAULT_LABEL: &str = "sig";

#[derive(Debug, Clone)]
pub struct VerifyOptions {
    pub max_age_secs: u64,
    pub clock_skew_secs: i64,
    pub require_authorization: bool,
    pub label: Option<String>,
}

impl Default for VerifyOptions {
    fn default() -> Self {
        Self {
            max_age_secs: DEFAULT_MAX_AGE_SECS,
            clock_skew_secs: DEFAULT_CLOCK_SKEW_SECS,
            require_authorization: false,
            label: None,
        }
    }
}

#[derive(Debug, Clone)]
pub struct VerifiedHttpSignature {
    pub label: String,
    pub signature_key: SignatureKey,
    pub public_jwk: PublicJwk,
    pub thumbprint: String,
    /// Present when `scheme=jwt`.
    pub jwt: Option<String>,
}

pub fn verify(
    method: &str,
    authority: &str,
    path: &str,
    headers: &HeaderMap,
    options: &VerifyOptions,
) -> Result<VerifiedHttpSignature> {
    let label = options.label.as_deref().unwrap_or(DEFAULT_LABEL);

    let signature_key_hdr = header_value(headers, &SIGNATURE_KEY)
        .ok_or(Error::MissingSignatureKey)?
        .to_string();
    let signature_input = header_value(headers, &SIGNATURE_INPUT)
        .ok_or(Error::MissingSignatureInput)?
        .to_string();
    let signature_hdr = header_value(headers, &SIGNATURE)
        .ok_or(Error::MissingSignature)?
        .to_string();

    let signature_key = SignatureKey::from_header(&signature_key_hdr, label)?;

    let header_map = HttpSignatureHeaders::try_parse(&signature_hdr, &signature_input)?;
    let sig_headers = header_map.get(label).ok_or(Error::InvalidSignatureFormat)?;
    let params = sig_headers.signature_params();

    let covered: Vec<String> = params
        .covered_components
        .iter()
        .map(|c| c.to_string().trim_matches('"').to_string())
        .collect();

    for required in ["@method", "@authority", "@path", SIGNATURE_KEY_NAME] {
        if !covered.iter().any(|c| c == required) {
            return Err(Error::MissingComponent(required));
        }
    }
    if options.require_authorization && !covered.iter().any(|c| c == AUTHORIZATION.as_str()) {
        return Err(Error::MissingComponent("authorization"));
    }

    let created = params.created.ok_or(Error::MissingCreated)?;
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs();
    if created > now + options.clock_skew_secs as u64 {
        return Err(Error::CreatedInFuture);
    }
    if now.saturating_sub(created) > options.max_age_secs + options.clock_skew_secs as u64 {
        return Err(Error::Expired);
    }

    let (public_jwk, jwt) = resolve_public_jwk(&signature_key)?;
    let thumbprint = jwk_thumbprint(&public_jwk)?;
    let verifying_key = public_key_from_jwk(&public_jwk)?;

    let mut component_lines = Vec::new();
    for id in &params.covered_components {
        let name = id.to_string().trim_matches('"').to_string();
        let value = match name.as_str() {
            "@method" => method.to_uppercase(),
            "@authority" => authority.to_string(),
            "@path" => path.to_string(),
            SIGNATURE_KEY_NAME => signature_key_hdr.clone(),
            other => header_value(
                headers,
                &HeaderName::from_bytes(other.as_bytes())
                    .map_err(|_| Error::MissingComponent("header"))?,
            )
            .ok_or_else(|| {
                if other == AUTHORIZATION.as_str() {
                    Error::AuthorizationHeaderMissing
                } else {
                    Error::MissingComponent("header")
                }
            })?
            .to_string(),
        };
        component_lines.push(HttpMessageComponent::try_from(
            format!("\"{name}\": {value}").as_str(),
        )?);
    }

    let base = HttpSignatureBase::try_new(&component_lines, params)?;
    base.verify_signature_headers(&verifying_key, sig_headers)
        .map_err(|_| Error::VerificationFailed)?;

    Ok(VerifiedHttpSignature {
        label: label.to_string(),
        signature_key,
        public_jwk,
        thumbprint,
        jwt,
    })
}

fn resolve_public_jwk(key: &SignatureKey) -> Result<(PublicJwk, Option<String>)> {
    match key {
        SignatureKey::Jwt(j) => {
            let jwk = cnf_jwk_from_jwt(&j.jwt)?;
            Ok((jwk, Some(j.jwt.clone())))
        }
        SignatureKey::Hwk(h) => Ok((h.jwk.clone(), None)),
        SignatureKey::Unsupported(s) => Err(Error::UnsupportedScheme(s.as_str().to_string())),
    }
}

#[derive(Deserialize)]
struct JwtPayload {
    cnf: Option<Cnf>,
}

#[derive(Deserialize)]
struct Cnf {
    jwk: Option<PublicJwk>,
}

fn cnf_jwk_from_jwt(jwt: &str) -> Result<PublicJwk> {
    let mut parts = jwt.split('.');
    let _header = parts
        .next()
        .ok_or_else(|| Error::InvalidJwt("missing header".into()))?;
    let payload_b64 = parts
        .next()
        .ok_or_else(|| Error::InvalidJwt("missing payload".into()))?;
    let payload_bytes = base64::Engine::decode(
        &base64::engine::general_purpose::URL_SAFE_NO_PAD,
        payload_b64,
    )
    .or_else(|_| base64::Engine::decode(&base64::engine::general_purpose::URL_SAFE, payload_b64))
    .map_err(|e| Error::InvalidJwt(e.to_string()))?;
    let payload: JwtPayload = serde_json::from_slice(&payload_bytes)?;
    payload.cnf.and_then(|c| c.jwk).ok_or(Error::MissingCnfJwk)
}

fn header_value<'a>(headers: &'a HeaderMap, name: &HeaderName) -> Option<&'a str> {
    headers.get(name).and_then(|v| v.to_str().ok())
}
