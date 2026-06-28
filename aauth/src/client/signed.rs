use std::future::Future;
use std::pin::Pin;
use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};

use async_trait::async_trait;
use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine as _};
use ed25519_dalek::{Signer, SigningKey};
use serde_json::Value;

use crate::error::{AAuthError, Result};
use crate::headers::{build_capabilities_header, build_mission_header};
use crate::http::{HttpRequest, HttpResponse};
use crate::types::{Capability, KeyMaterial, Mission, SignatureKey};

pub type SignedFetch = Arc<
    dyn Fn(HttpRequest) -> Pin<Box<dyn Future<Output = Result<HttpResponse>> + Send>> + Send + Sync,
>;

#[async_trait]
pub trait KeyMaterialProvider: Send + Sync {
    async fn key_material(&self) -> Result<KeyMaterial>;
}

#[derive(Debug, Clone, Default)]
pub struct SignedFetchOptions {
    pub capabilities: Option<Vec<Capability>>,
    pub mission: Option<Mission>,
}

pub fn create_signed_fetch(
    client: Arc<dyn HttpClientAdapter>,
    provider: Arc<dyn KeyMaterialProvider>,
    options: Option<SignedFetchOptions>,
) -> SignedFetch {
    let mut builder = SignedFetchBuilder::new(client, provider);
    if let Some(opts) = options {
        builder = builder.options(opts);
    }
    builder.build()
}

struct SignedFetchBuilder {
    client: Arc<dyn HttpClientAdapter>,
    provider: Arc<dyn KeyMaterialProvider>,
    options: SignedFetchOptions,
}

impl SignedFetchBuilder {
    fn new(client: Arc<dyn HttpClientAdapter>, provider: Arc<dyn KeyMaterialProvider>) -> Self {
        Self {
            client,
            provider,
            options: SignedFetchOptions::default(),
        }
    }

    fn options(mut self, options: SignedFetchOptions) -> Self {
        self.options = options;
        self
    }

    fn build(self) -> SignedFetch {
        let client = self.client;
        let provider = self.provider;
        let options = self.options;
        Arc::new(move |mut request: HttpRequest| {
            let client = Arc::clone(&client);
            let provider = Arc::clone(&provider);
            let options = options.clone();
            Box::pin(async move {
                let material = provider.key_material().await?;
                apply_optional_headers(&mut request, &options);
                sign_request(&mut request, &material)?;
                client.send(request).await
            })
        })
    }
}

#[async_trait]
pub trait HttpClientAdapter: Send + Sync {
    async fn send(&self, request: HttpRequest) -> Result<HttpResponse>;
}

#[async_trait]
impl HttpClientAdapter for crate::http::ReqwestClient {
    async fn send(&self, request: HttpRequest) -> Result<HttpResponse> {
        use crate::http::HttpClient;
        HttpClient::send(self, request)
            .await
            .map_err(AAuthError::Http)
    }
}

fn apply_optional_headers(request: &mut HttpRequest, options: &SignedFetchOptions) {
    if let Some(capabilities) = &options.capabilities {
        if !capabilities.is_empty() {
            request.headers.insert(
                "aauth-capabilities".to_string(),
                build_capabilities_header(capabilities),
            );
        }
    }
    if let Some(mission) = &options.mission {
        request
            .headers
            .insert("aauth-mission".to_string(), build_mission_header(mission));
    }
}

pub(crate) fn sign_request(request: &mut HttpRequest, material: &KeyMaterial) -> Result<()> {
    let token = match &material.signature_key {
        SignatureKey::Jwt(j) => &j.jwt,
        SignatureKey::JktJwt(j) => &j.jwt,
        SignatureKey::Hwk(_) => {
            return Err(AAuthError::Message(
                "hwk signature key not supported for AAuth requests".into(),
            ))
        }
    };
    let jwt = format!("sig=jwt;jwt=\"{token}\"");

    request
        .headers
        .insert("signature-key".to_string(), jwt.clone());

    let signing_key = signing_key_from_jwk(&material.signing_jwk)?;
    let created = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs();

    let signature_input =
        format!("sig=(\"@method\" \"@authority\" \"@path\" \"signature-key\");created={created}");
    let signature_base = build_signature_base(request, &jwt, created);
    let signature_bytes = signing_key.sign(signature_base.as_bytes());
    let signature = URL_SAFE_NO_PAD.encode(signature_bytes.to_bytes());

    request
        .headers
        .insert("signature-input".to_string(), signature_input);
    request
        .headers
        .insert("signature".to_string(), format!("sig=:{signature}:"));

    Ok(())
}

pub fn sign_request_with_auth_token(
    request: &mut HttpRequest,
    material: &KeyMaterial,
    auth_token: &str,
) -> Result<()> {
    let mut auth_material = material.clone();
    auth_material.signature_key = SignatureKey::Jwt(crate::types::SignatureKeyJwt {
        jwt: auth_token.to_string(),
    });
    sign_request(request, &auth_material)
}

fn build_signature_base(request: &HttpRequest, signature_key: &str, created: u64) -> String {
    let url = url::Url::parse(&request.url).expect("valid request url");
    let authority = url.authority();
    let path = url.path();
    format!(
        "\"@method\": {}\n\"@authority\": {}\n\"@path\": {}\n\"signature-key\": {}\n\"@signature-params\": (\"@method\" \"@authority\" \"@path\" \"signature-key\");created={created}",
        request.method.to_lowercase(),
        authority,
        path,
        signature_key,
    )
}

fn signing_key_from_jwk(jwk: &Value) -> Result<SigningKey> {
    let d = jwk
        .get("d")
        .and_then(|v| v.as_str())
        .ok_or_else(|| AAuthError::Message("signing JWK missing private key".into()))?;
    let bytes = URL_SAFE_NO_PAD
        .decode(d)
        .map_err(|e| AAuthError::Message(e.to_string()))?;
    let key_bytes: [u8; 32] = bytes
        .try_into()
        .map_err(|_| AAuthError::Message("invalid Ed25519 private key length".into()))?;
    Ok(SigningKey::from_bytes(&key_bytes))
}

#[cfg(test)]
mod tests {
    use std::collections::HashMap;

    use super::*;

    #[test]
    fn signature_base_includes_components() {
        let request = HttpRequest {
            method: "GET".into(),
            url: "https://resource.example/api/data".into(),
            headers: HashMap::new(),
            body: None,
        };
        let base = build_signature_base(&request, "sig=jwt;jwt=\"abc\"", 1);
        assert!(base.contains("@method"));
        assert!(base.contains("@authority"));
        assert!(base.contains("@path"));
        assert!(base.contains("signature-key"));
    }
}
