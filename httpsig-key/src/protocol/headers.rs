//! Header names for Signature / Signature-Key / Signature-Error.
//!
//! Spec: `draft-hardt-httpbis-signature-key-05.txt` §3, §5

use http::HeaderName;

/// Lowercase name for [`SIGNATURE`].
pub const SIGNATURE_NAME: &str = "signature";

pub const SIGNATURE: HeaderName = HeaderName::from_static(SIGNATURE_NAME);

/// Lowercase name for [`SIGNATURE_INPUT`].
pub const SIGNATURE_INPUT_NAME: &str = "signature-input";

pub const SIGNATURE_INPUT: HeaderName = HeaderName::from_static(SIGNATURE_INPUT_NAME);

/// Lowercase name for [`SIGNATURE_KEY`] (also used as a covered component).
///
/// Spec: `draft-hardt-httpbis-signature-key-05.txt` §3
pub const SIGNATURE_KEY_NAME: &str = "signature-key";

pub const SIGNATURE_KEY: HeaderName = HeaderName::from_static(SIGNATURE_KEY_NAME);

/// Lowercase name for [`SIGNATURE_ERROR`].
///
/// Spec: `draft-hardt-httpbis-signature-key-05.txt` §5
pub const SIGNATURE_ERROR_NAME: &str = "signature-error";

pub const SIGNATURE_ERROR: HeaderName = HeaderName::from_static(SIGNATURE_ERROR_NAME);
