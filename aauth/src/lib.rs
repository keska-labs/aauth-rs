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
pub mod keys;
pub mod metadata;
pub mod types;

#[cfg(feature = "client")]
pub mod client;

#[cfg(feature = "server")]
pub mod server;

pub use error::{AAuthError, Result, TokenError};
pub use headers::{
    build_aauth_requirement, build_capabilities_header, build_mission_header,
    parse_aauth_requirement, parse_capabilities_header, parse_mission_header,
};
pub use interaction_code::{canonicalize_code, generate_code};
pub use jwt::{
    jwk_set_from_okp, jwk_thumbprint, ActClaim, AgentClaims, AuthClaims, CnfClaim, OkpJwk,
    OkpSigningJwk, ResourceClaims, VerifiedToken,
};
pub use keys::{
    create_test_keys, static_agent_metadata_fetcher, static_auth_metadata_fetcher,
    Ed25519KeyPair, OkpSigningKey, TestKeys,
};
#[cfg(feature = "client")]
pub use client::keys::{
    create_key_provider, mint_agent_jwt, AgentJwtMinter, StaticKeyMaterialProvider,
    TestAgentJwtMinter,
};
#[cfg(feature = "server")]
pub use server::keys::{
    mint_auth_jwt, AuthJwtMinter, Ed25519ResourceTokenSigner, ResourceTokenSigner,
    TestAuthJwtMinter,
};
pub use metadata::{
    clear_metadata_cache, CachedMetadataFetcher, MetadataFetcher, StaticMetadataFetcher,
};
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
    PendingRequest, ResourceTokenOptions, VerifyTokenOptions,
};
