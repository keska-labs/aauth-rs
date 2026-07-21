//! Wire types for HTTP Signature Keys.
//!
//! Spec: `draft-hardt-httpbis-signature-key-05.txt`

mod headers;
mod jwk;
mod sigkey;
mod signature_error;
mod signature_key;

pub use headers::{
    SIGNATURE, SIGNATURE_ERROR, SIGNATURE_ERROR_NAME, SIGNATURE_INPUT, SIGNATURE_INPUT_NAME,
    SIGNATURE_KEY, SIGNATURE_KEY_NAME, SIGNATURE_NAME,
};
pub use jwk::{PublicJwk, SigningJwk};
pub use sigkey::SigkeyValue;
pub use signature_error::SignatureErrorHeader;
pub use signature_key::{
    SignatureKey, SignatureKeyHwk, SignatureKeyJwt, SignatureKeyScheme, SigningMaterial,
};
