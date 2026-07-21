use std::time::{SystemTime, UNIX_EPOCH};

use aauth::SignatureError;
use aauth::protocol::SignatureKeyJwt;
use aauth::protocol::{
    AAUTH_CAPABILITIES, AAUTH_MISSION, Capability, KeyMaterial, Mission, SIGNATURE,
    SIGNATURE_INPUT, SIGNATURE_KEY, SIGNATURE_KEY_NAME, SignatureKey,
};
use aauth::signature::{build_signature_base_with_extras, sign_http_message};
use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use http::header::{AUTHORIZATION, HeaderValue};
use reqwest::Request;

use crate::error::Result;

#[derive(Debug, Clone, Default)]
pub struct SigningOptions {
    pub capabilities: Option<Vec<Capability>>,
    pub mission: Option<Mission>,
}

impl SigningOptions {
    /// Set `AAuth-Capabilities` / `AAuth-Mission` on the request when configured.
    pub fn apply_to(&self, request: &mut Request) {
        if let Some(capabilities) = &self.capabilities {
            if !capabilities.is_empty() {
                request.headers_mut().insert(
                    AAUTH_CAPABILITIES,
                    HeaderValue::from_str(&Capability::join_header(capabilities))
                        .expect("valid capabilities header"),
                );
            }
        }
        if let Some(mission) = &self.mission {
            request.headers_mut().insert(
                AAUTH_MISSION,
                HeaderValue::from_str(&mission.to_header()).expect("valid mission header"),
            );
        }
    }
}

pub(crate) fn apply_opaque_token(request: &mut Request, token: &str) {
    request.headers_mut().insert(
        AUTHORIZATION,
        HeaderValue::from_str(&format!("AAuth {token}")).expect("valid authorization header"),
    );
}

/// Signing helpers for [`KeyMaterial`] against a `reqwest::Request`.
pub trait SignRequest {
    fn sign_request(&self, request: &mut Request) -> Result<()>;

    fn sign_request_with_auth_token(&self, request: &mut Request, auth_token: &str) -> Result<()>;
}

impl SignRequest for KeyMaterial {
    fn sign_request(&self, request: &mut Request) -> Result<()> {
        let token = match &self.signature_key {
            SignatureKey::Jwt(j) => &j.jwt,
            SignatureKey::JktJwt(j) => &j.jwt,
            SignatureKey::Hwk(_) => {
                return Err(SignatureError::HwkUnsupported.into());
            }
        };
        let signature_key = format!("sig=jwt;jwt=\"{token}\"");

        request.headers_mut().insert(
            SIGNATURE_KEY,
            HeaderValue::from_str(&signature_key).map_err(SignatureError::InvalidHeaderValue)?,
        );

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
            SIGNATURE_KEY_NAME.to_string(),
        ];
        let mut extras = Vec::new();
        if let Some(ref auth) = authorization {
            covered.push(AUTHORIZATION.as_str().to_string());
            extras.push((AUTHORIZATION.as_str().to_string(), auth.clone()));
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
        let signature_bytes = sign_http_message(&self.signing_jwk, signature_base.as_bytes())?;
        let signature = URL_SAFE_NO_PAD.encode(signature_bytes);

        request.headers_mut().insert(
            SIGNATURE_INPUT,
            HeaderValue::from_str(&signature_input).map_err(SignatureError::InvalidHeaderValue)?,
        );
        request.headers_mut().insert(
            SIGNATURE,
            HeaderValue::from_str(&format!("sig=:{signature}:"))
                .map_err(SignatureError::InvalidHeaderValue)?,
        );

        Ok(())
    }

    fn sign_request_with_auth_token(&self, request: &mut Request, auth_token: &str) -> Result<()> {
        let mut auth_material = self.clone();
        auth_material.signature_key = SignatureKey::Jwt(SignatureKeyJwt {
            jwt: auth_token.to_string(),
        });
        auth_material.sign_request(request)
    }
}
