use std::time::{SystemTime, UNIX_EPOCH};

use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use ed25519_dalek::Signer;
use http::header::{AUTHORIZATION, HeaderName, HeaderValue};
use reqwest::Request;

use crate::error::{AAuthError, Result};
use crate::protocol::{Capability, KeyMaterial, Mission, SignatureKey};
use crate::protocol::{build_capabilities_header, build_mission_header};
use crate::signature::{build_signature_base_with_extras, signing_key_from_jwk};

#[derive(Debug, Clone, Default)]
pub struct SigningOptions {
    pub capabilities: Option<Vec<Capability>>,
    pub mission: Option<Mission>,
}

pub fn apply_capability_mission(request: &mut Request, options: &SigningOptions) {
    if let Some(capabilities) = &options.capabilities {
        if !capabilities.is_empty() {
            request.headers_mut().insert(
                HeaderName::from_static("aauth-capabilities"),
                HeaderValue::from_str(&build_capabilities_header(capabilities))
                    .expect("valid capabilities header"),
            );
        }
    }
    if let Some(mission) = &options.mission {
        request.headers_mut().insert(
            HeaderName::from_static("aauth-mission"),
            HeaderValue::from_str(&build_mission_header(mission)).expect("valid mission header"),
        );
    }
}

pub fn apply_opaque_token(request: &mut Request, token: &str) {
    request.headers_mut().insert(
        AUTHORIZATION,
        HeaderValue::from_str(&format!("AAuth {token}")).expect("valid authorization header"),
    );
}

pub fn sign_request(request: &mut Request, material: &KeyMaterial) -> Result<()> {
    let token = match &material.signature_key {
        SignatureKey::Jwt(j) => &j.jwt,
        SignatureKey::JktJwt(j) => &j.jwt,
        SignatureKey::Hwk(_) => {
            return Err(AAuthError::Message(
                "hwk signature key not supported for AAuth requests".into(),
            ));
        }
    };
    let signature_key = format!("sig=jwt;jwt=\"{token}\"");

    request.headers_mut().insert(
        HeaderName::from_static("signature-key"),
        HeaderValue::from_str(&signature_key).map_err(|e| AAuthError::Message(e.to_string()))?,
    );

    let signing_key = signing_key_from_jwk(&material.signing_jwk)?;
    let created = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs();

    let authorization = request
        .headers()
        .get(AUTHORIZATION)
        .and_then(|v| v.to_str().ok())
        .filter(|v| v.starts_with("AAuth "))
        .map(str::to_string);

    let mut covered = vec![
        "@method".to_string(),
        "@authority".to_string(),
        "@path".to_string(),
        "signature-key".to_string(),
    ];
    let mut extras = Vec::new();
    if let Some(ref auth) = authorization {
        covered.push("authorization".to_string());
        extras.push(("authorization".to_string(), auth.clone()));
    }

    let signature_input = format!(
        "sig=({});created={created}",
        covered
            .iter()
            .map(|c| format!("\"{c}\""))
            .collect::<Vec<_>>()
            .join(" ")
    );
    let url = request.url();
    let extra_refs: Vec<(&str, &str)> = extras
        .iter()
        .map(|(k, v)| (k.as_str(), v.as_str()))
        .collect();
    let signature_base = build_signature_base_with_extras(
        request.method().as_str(),
        url.authority(),
        url.path(),
        &signature_key,
        created,
        &extra_refs,
    )
    .0;
    let signature_bytes = signing_key.sign(signature_base.as_bytes());
    let signature = URL_SAFE_NO_PAD.encode(signature_bytes.to_bytes());

    request.headers_mut().insert(
        HeaderName::from_static("signature-input"),
        HeaderValue::from_str(&signature_input).map_err(|e| AAuthError::Message(e.to_string()))?,
    );
    request.headers_mut().insert(
        HeaderName::from_static("signature"),
        HeaderValue::from_str(&format!("sig=:{signature}:"))
            .map_err(|e| AAuthError::Message(e.to_string()))?,
    );

    Ok(())
}

pub fn sign_request_with_auth_token(
    request: &mut Request,
    material: &KeyMaterial,
    auth_token: &str,
) -> Result<()> {
    let mut auth_material = material.clone();
    auth_material.signature_key = SignatureKey::Jwt(crate::protocol::SignatureKeyJwt {
        jwt: auth_token.to_string(),
    });
    sign_request(request, &auth_material)
}
