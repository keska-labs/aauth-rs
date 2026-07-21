//! Sign HTTP requests with Signature-Key + RFC 9421 Signature / Signature-Input.
//!
//! Spec: `draft-hardt-httpbis-signature-key-05.txt` §3

use std::time::{SystemTime, UNIX_EPOCH};

use http::HeaderMap;
use httpsig::prelude::{
    HttpSignatureBase, HttpSignatureParams,
    message_component::{HttpMessageComponent, HttpMessageComponentId},
};

use crate::crypto::secret_key_from_signing_jwk;
use crate::error::{Error, Result};
use crate::protocol::{
    SIGNATURE, SIGNATURE_INPUT, SIGNATURE_KEY, SIGNATURE_KEY_NAME, SignatureKey, SigningMaterial,
};

const DEFAULT_LABEL: &str = "sig";

#[derive(Debug, Clone, Default)]
pub struct SignOptions {
    /// Extra covered header components as `(name, value)` pairs already present on the request.
    pub extras: Vec<(String, String)>,
    pub label: Option<String>,
}

/// Sign `headers` in place for the given request components and material.
pub fn sign(
    headers: &mut HeaderMap,
    method: &str,
    authority: &str,
    path: &str,
    material: &SigningMaterial,
    options: &SignOptions,
) -> Result<()> {
    match &material.signature_key {
        SignatureKey::Jwt(_) | SignatureKey::Hwk(_) => {}
        SignatureKey::Unsupported(s) => {
            return Err(Error::UnsupportedScheme(s.as_str().to_string()));
        }
    }

    let label = options.label.as_deref().unwrap_or(DEFAULT_LABEL);
    let signature_key_header = material.signature_key.to_header(label)?;

    headers.insert(
        SIGNATURE_KEY,
        http::HeaderValue::from_str(&signature_key_header).map_err(Error::InvalidHeaderValue)?,
    );

    let mut component_ids = vec![
        HttpMessageComponentId::try_from("@method")?,
        HttpMessageComponentId::try_from("@authority")?,
        HttpMessageComponentId::try_from("@path")?,
        HttpMessageComponentId::try_from(SIGNATURE_KEY_NAME)?,
    ];
    for (name, _) in &options.extras {
        component_ids.push(HttpMessageComponentId::try_from(name.as_str())?);
    }

    let mut params = HttpSignatureParams::try_new(&component_ids)?;
    let created = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs();
    params.set_created(created);

    let mut component_lines = vec![
        HttpMessageComponent::try_from(format!("\"@method\": {}", method.to_uppercase()).as_str())?,
        HttpMessageComponent::try_from(format!("\"@authority\": {authority}").as_str())?,
        HttpMessageComponent::try_from(format!("\"@path\": {path}").as_str())?,
        HttpMessageComponent::try_from(
            format!("\"{SIGNATURE_KEY_NAME}\": {signature_key_header}").as_str(),
        )?,
    ];
    for (name, value) in &options.extras {
        component_lines.push(HttpMessageComponent::try_from(
            format!("\"{name}\": {value}").as_str(),
        )?);
    }

    let base = HttpSignatureBase::try_new(&component_lines, &params)?;
    let secret = secret_key_from_signing_jwk(&material.signing_jwk)?;
    let sig_headers = base.build_signature_headers(&secret, Some(label))?;

    headers.insert(
        SIGNATURE_INPUT,
        http::HeaderValue::from_str(&sig_headers.signature_input_header_value())
            .map_err(Error::InvalidHeaderValue)?,
    );
    headers.insert(
        SIGNATURE,
        http::HeaderValue::from_str(&sig_headers.signature_header_value())
            .map_err(Error::InvalidHeaderValue)?,
    );

    Ok(())
}
