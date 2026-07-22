//! Small shared HTTP helpers used across roles.

use http::header::{AUTHORIZATION, HOST, HeaderName};
use http::{HeaderMap, Request};
use httpsig_key::{SignOptions, SignatureKey, SignatureKeyJwt, SigningMaterial, sign};

use crate::error::{Result, SignatureError};
use crate::protocol::{AAUTH_MISSION, AAUTH_MISSION_NAME};

/// Trim trailing `/` and lowercase for URL equality checks (audience / issuer binding).
#[cfg(feature = "resource-verify")]
pub(crate) fn normalize_server_url(url: &str) -> String {
    url.trim_end_matches('/').to_lowercase()
}

pub(crate) fn header_value<'a>(headers: &'a HeaderMap, name: &HeaderName) -> Option<&'a str> {
    headers.get(name).and_then(|v| v.to_str().ok())
}

/// Derive `@method`, `@authority`, and `@path` from an HTTP request.
///
/// Authority prefers the `Host` header, then the URI host/port.
pub fn signature_parts<B>(req: &Request<B>) -> (String, String, String) {
    let method = req.method().as_str().to_string();
    let uri = req.uri();
    let authority = req
        .headers()
        .get(HOST)
        .and_then(|h| h.to_str().ok())
        .map(str::to_string)
        .unwrap_or_else(|| {
            uri.host()
                .map(|host| match uri.port_u16() {
                    Some(port) => format!("{host}:{port}"),
                    None => host.to_string(),
                })
                .unwrap_or_default()
        });
    let path = uri.path().to_string();
    (method, authority, path)
}

/// Build [`SignOptions`] extras from request headers for AAuth signing.
///
/// Auto-covers:
/// - `authorization` when `Authorization: AAuth …` is present
/// - `aauth-mission` when `AAuth-Mission` is present
///
/// Spec: `#aauth-access`, `#http-message-signatures-profile`, `#aauth-mission-request-header`
pub fn aauth_sign_options(headers: &HeaderMap) -> SignOptions {
    let mut options = SignOptions::default();

    if let Some(auth) = headers
        .get(AUTHORIZATION)
        .and_then(|v| v.to_str().ok())
        .filter(|v| v.starts_with("AAuth "))
    {
        options
            .extras
            .push((AUTHORIZATION.as_str().to_string(), auth.to_string()));
    }

    if let Some(mission) = headers.get(AAUTH_MISSION).and_then(|v| v.to_str().ok()) {
        options
            .extras
            .push((AAUTH_MISSION_NAME.to_string(), mission.to_string()));
    }

    options
}

/// Extension trait: sign an [`http::Request`] with [`SigningMaterial`].
///
/// Covers the AAuth base components plus request-state extras via [`aauth_sign_options`].
pub trait RequestSigningExt: Sized {
    fn sign(&mut self, key_material: &SigningMaterial) -> Result<()>;

    fn sign_with_auth_token(
        &mut self,
        key_material: &SigningMaterial,
        auth_token: &str,
    ) -> Result<()>;

    fn signed(mut self, key_material: &SigningMaterial) -> Result<Self> {
        self.sign(key_material)?;
        Ok(self)
    }

    fn signed_with_auth_token(
        mut self,
        key_material: &SigningMaterial,
        auth_token: &str,
    ) -> Result<Self> {
        self.sign_with_auth_token(key_material, auth_token)?;
        Ok(self)
    }
}

impl<B> RequestSigningExt for Request<B> {
    fn sign(&mut self, key_material: &SigningMaterial) -> Result<()> {
        match &key_material.signature_key {
            SignatureKey::Jwt(_) => {}
            SignatureKey::Hwk(_) | SignatureKey::Unsupported(_) => {
                return Err(SignatureError::HwkUnsupported.into());
            }
        }

        let (method, authority, path) = signature_parts(self);
        if authority.is_empty() {
            return Err(SignatureError::MissingAuthority.into());
        }

        let options = aauth_sign_options(self.headers());
        sign(
            self.headers_mut(),
            &method,
            &authority,
            &path,
            key_material,
            &options,
        )?;
        Ok(())
    }

    fn sign_with_auth_token(
        &mut self,
        key_material: &SigningMaterial,
        auth_token: &str,
    ) -> Result<()> {
        let mut auth_material = key_material.clone();
        auth_material.signature_key = SignatureKey::Jwt(SignatureKeyJwt {
            jwt: auth_token.to_string(),
        });
        self.sign(&auth_material)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::protocol::{SignatureKey, SignatureKeyJwt};
    use crate::{RequestSigningExt, TestKeys};
    use http::header::HeaderValue;
    use httpsig_key::{VerifyOptions, verify};

    #[test]
    fn signed_covers_authorization_and_mission() {
        let keys = TestKeys::generate();
        let issuer = "https://example.com";
        let agent_jwt = keys.mint_agent_jwt(issuer, "aauth:test@example.com", None);
        let material = SigningMaterial {
            signing_jwk: keys.agent_ephemeral.signing_jwk(),
            signature_key: SignatureKey::Jwt(SignatureKeyJwt { jwt: agent_jwt }),
        };

        let mission = r#"approver="https://ps.example";s256="abc""#;
        let req = Request::builder()
            .method("GET")
            .uri("/api/data")
            .header(HOST, HeaderValue::from_static("resource.example"))
            .header(
                AUTHORIZATION,
                HeaderValue::from_static("AAuth opaque-token"),
            )
            .header(AAUTH_MISSION, HeaderValue::from_str(mission).unwrap())
            .body(())
            .unwrap()
            .signed(&material)
            .unwrap();

        let input = req
            .headers()
            .get("signature-input")
            .and_then(|v| v.to_str().ok())
            .unwrap();
        assert!(
            input.contains("\"authorization\""),
            "Signature-Input should cover authorization: {input}"
        );
        assert!(
            input.contains("\"aauth-mission\""),
            "Signature-Input should cover aauth-mission: {input}"
        );

        let (method, authority, path) = signature_parts(&req);
        verify(
            &method,
            &authority,
            &path,
            req.headers(),
            &VerifyOptions {
                require_authorization: true,
                ..VerifyOptions::default()
            },
        )
        .expect("verify with covered authorization");
    }
}
