//! Rust implementation of the [AAuth authorization protocol](https://github.com/dickhardt/AAuth).
//!
//! # Features
//!
//! - `client` — framework-agnostic auth flow and key material (`client::injector`, `client::keys`)
//! - `client-reqwest` — reqwest middleware and token exchange (`client::reqwest`)
//! - `server` — token verification, resource token creation, interaction management
//! - `server-axum` — axum middleware and route helpers (`server::axum`)
//!
//! # Protocol roles
//!
//! - **Agent** — [`client`]
//! - **Resource server** — [`server::resource`]
//! - **Person server** — [`server::person`]
//! - **Access server** — [`server::access`]

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
#[cfg(feature = "client")]
pub use client::resolve::{
    agent_jwt_from_signature_key, person_server_from_agent_jwt, resolve_person_server_url,
    resource_token_audience_unverified,
};
pub use error::{AAuthError, Result, TokenError};
pub use headers::{
    build_aauth_requirement, build_capabilities_header, build_mission_header,
    parse_aauth_requirement, parse_capabilities_header, parse_mission_header,
};
pub use interaction_code::{canonicalize_code, generate_code};
pub use jwt::{
    ActClaim, AgentClaims, AuthClaims, CnfClaim, OkpJwk, OkpSigningJwk, ResourceClaims,
    VerifiedToken, decode_resource_token_unverified, jwk_set_from_okp, jwk_thumbprint,
};
pub use keys::{
    Ed25519KeyPair, OkpSigningKey, TestKeys, create_test_keys, static_agent_metadata_fetcher,
    static_person_metadata_fetcher,
};
pub use metadata::{MetadataFetcher, StaticMetadataFetcher};
#[cfg(all(feature = "server", feature = "server-axum"))]
pub use server::access::{
    AccessAuthJwtMinter, AccessServerMetadata, TestAccessAuthJwtMinter, mint_access_auth_jwt,
};
#[cfg(feature = "server")]
pub use server::{
    AuthJwtMinter, Ed25519ResourceTokenSigner, InMemoryOpaqueAccessStore, InteractionManager,
    InteractionManagerOptions, OpaqueAccessStore, PendingRequest, ResourceAccessPolicy,
    ResourceTokenOptions, ResourceTokenSigner, TestAuthJwtMinter, VerifyResourceTokenOptions,
    VerifyTokenOptions, create_resource_token, mint_auth_jwt, resolve_resource_token_audience,
    verify_resource_token, verify_token,
};
pub use types::*;
