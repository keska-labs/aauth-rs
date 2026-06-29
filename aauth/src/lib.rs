//! Rust implementation of the [AAuth authorization protocol](https://github.com/dickhardt/AAuth).
//!
//! # Features
//!
//! - `client` — signed HTTP requests, token exchange, and protocol-aware fetch (`client::reqwest`)
//! - `server` — token verification, resource token creation, interaction management
//! - `server-axum` — axum middleware and route helpers (`server::axum`)

pub mod error;
pub mod headers;
pub mod interaction_code;
pub mod jwt;
pub mod keys;
pub mod metadata;
pub mod signature;
pub mod types;

#[cfg(feature = "client")]
pub mod client;

#[cfg(feature = "server")]
pub mod server;

#[cfg(feature = "client")]
pub use client::keys::{
    AgentJwtMinter, KeyMaterialProvider, StaticKeyMaterialProvider, TestAgentJwtMinter,
    create_key_provider, mint_agent_jwt,
};
pub use error::{AAuthError, Result, TokenError};
pub use headers::{
    build_aauth_requirement, build_capabilities_header, build_mission_header,
    parse_aauth_requirement, parse_capabilities_header, parse_mission_header,
};
pub use interaction_code::{canonicalize_code, generate_code};
pub use jwt::{
    ActClaim, AgentClaims, AuthClaims, CnfClaim, OkpJwk, OkpSigningJwk, ResourceClaims,
    VerifiedToken, jwk_set_from_okp, jwk_thumbprint,
};
pub use keys::{
    Ed25519KeyPair, OkpSigningKey, TestKeys, create_test_keys, static_agent_metadata_fetcher,
    static_auth_metadata_fetcher,
};
pub use metadata::{
    CachedMetadataFetcher, MetadataFetcher, StaticMetadataFetcher, clear_metadata_cache,
};
#[cfg(feature = "server")]
pub use server::keys::{
    AuthJwtMinter, Ed25519ResourceTokenSigner, ResourceTokenSigner, TestAuthJwtMinter,
    mint_auth_jwt,
};
pub use types::*;

#[cfg(feature = "server")]
pub use server::{
    InteractionManager, InteractionManagerOptions, PendingRequest, ResourceTokenOptions,
    VerifyTokenOptions, create_resource_token, verify_token,
};
