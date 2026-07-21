//! HTTP Signature Keys on top of [`httpsig`] (RFC 9421).
//!
//! Spec: [`draft-hardt-httpbis-signature-key-05.txt`](../docs/specs/draft-hardt-httpbis-signature-key-05.txt)

mod crypto;
mod error;
pub mod protocol;
mod sign;
mod thumbprint;
mod verify;

pub use crypto::{public_key_from_jwk, secret_key_from_signing_jwk};
pub use error::{Error, Result};
pub use protocol::{
    PublicJwk, SIGNATURE, SIGNATURE_ERROR, SIGNATURE_ERROR_NAME, SIGNATURE_INPUT,
    SIGNATURE_INPUT_NAME, SIGNATURE_KEY, SIGNATURE_KEY_NAME, SIGNATURE_NAME, SigkeyValue,
    SignatureErrorHeader, SignatureKey, SignatureKeyHwk, SignatureKeyJwt, SignatureKeyScheme,
    SigningJwk, SigningMaterial,
};
pub use sign::{SignOptions, sign};
pub use thumbprint::jwk_thumbprint;
pub use verify::{VerifiedHttpSignature, VerifyOptions, verify};
