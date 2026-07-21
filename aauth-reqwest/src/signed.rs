use aauth::SignatureError;
use aauth::protocol::{
    AAUTH_CAPABILITIES, AAUTH_MISSION, Capability, KeyMaterial, Mission, SignatureKey,
    SignatureKeyJwt,
};
use aauth::signature::sign_request_headers;
use http::header::{AUTHORIZATION, HeaderValue};
use reqwest::{Request, Response};

use crate::error::Result;

#[trait_variant::make(Send)]
#[dynosaur::dynosaur(DynSignedSend = dyn(box) SignedSend, bridge(dyn))]
pub(crate) trait SignedSend {
    async fn send(&mut self, req: Request) -> Result<Response>;
}

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

/// Extension trait: sign a `reqwest::Request` with [`KeyMaterial`].
pub trait RequestSigningExt: Sized {
    fn sign(&mut self, key_material: &KeyMaterial) -> Result<()>;

    fn sign_with_auth_token(&mut self, key_material: &KeyMaterial, auth_token: &str) -> Result<()>;

    fn signed(mut self, key_material: &KeyMaterial) -> Result<Self> {
        self.sign(key_material)?;
        Ok(self)
    }

    fn signed_with_auth_token(
        mut self,
        key_material: &KeyMaterial,
        auth_token: &str,
    ) -> Result<Self> {
        self.sign_with_auth_token(key_material, auth_token)?;
        Ok(self)
    }
}

impl RequestSigningExt for Request {
    fn sign(&mut self, key_material: &KeyMaterial) -> Result<()> {
        match &key_material.signature_key {
            SignatureKey::Jwt(_) | SignatureKey::JktJwt(_) => {}
            SignatureKey::Hwk(_) => {
                return Err(SignatureError::HwkUnsupported.into());
            }
        }

        let authorization = self
            .headers()
            .get(AUTHORIZATION)
            .and_then(|v| v.to_str().ok())
            .filter(|v| v.starts_with("AAuth "))
            .map(str::to_string);

        let method = self.method().as_str().to_string();
        let authority = self.url().authority().to_string();
        let path = self.url().path().to_string();
        sign_request_headers(
            self.headers_mut(),
            &method,
            &authority,
            &path,
            key_material,
            authorization.as_deref(),
        )?;

        Ok(())
    }

    fn sign_with_auth_token(&mut self, key_material: &KeyMaterial, auth_token: &str) -> Result<()> {
        let mut auth_material = key_material.clone();
        auth_material.signature_key = SignatureKey::Jwt(SignatureKeyJwt {
            jwt: auth_token.to_string(),
        });
        self.sign(&auth_material)
    }
}
