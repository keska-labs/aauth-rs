//! Rust implementation of the [AAuth authorization protocol](https://github.com/dickhardt/AAuth).
//!
//! # Features
//!
//! - `client` — signed HTTP requests, token exchange, and protocol-aware fetch
//! - `server` — token verification, resource token creation, interaction management
//!
//! Both features are enabled by default.

pub mod error;
pub mod headers;
pub mod http;
pub mod interaction_code;
pub mod jwt;
pub mod metadata;
pub mod types;

#[cfg(feature = "client")]
pub mod client;

#[cfg(feature = "server")]
pub mod server;

pub use error::{AAuthError, Result, TokenError};
pub use headers::{
    build_aauth_access, build_aauth_requirement, build_capabilities_header, build_mission_header,
    parse_aauth_requirement, parse_capabilities_header, parse_mission_header,
};
pub use interaction_code::{canonicalize_code, generate_code};
pub use jwt::{decode_jwt_payload, jwk_thumbprint, jwt_typ};
pub use metadata::{clear_metadata_cache, CachedMetadataFetcher, MetadataFetcher};
pub use types::*;

#[cfg(feature = "client")]
pub use client::{
    create_aauth_fetch, create_signed_fetch, exchange_token, poll_deferred, AAuthFetch,
    AAuthFetchOptions, DeferredOptions, DeferredResult, InteractionCallback, SignedFetch,
    SignedFetchOptions, TokenExchangeError, TokenExchangeOptions, TokenExchangeResult,
};

#[cfg(feature = "server")]
pub use server::{
    create_resource_token, verify_token, InteractionManager, InteractionManagerOptions,
    PendingRequest, ResourceTokenOptions, SignFn, VerifyTokenOptions,
};
