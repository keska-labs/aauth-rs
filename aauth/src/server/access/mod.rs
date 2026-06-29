//! Access Server (AS) support for federated four-party AAuth.
//!
//! In federated access mode, the resource delegates policy evaluation to an Access Server.
//! The Person Server federates with the AS by calling its token endpoint; the AS issues
//! auth tokens with `dwk: aauth-access.json` (discovered at `{as_url}/.well-known/aauth-access.json`).
//!
//! This module is a placeholder until PS→AS federation and AS token endpoints are implemented.

pub use crate::types::AccessServerMetadata;
