pub mod keys;

#[cfg(feature = "server-axum")]
pub mod axum;

mod audience;
mod opaque;
mod policy;
mod token;
mod verify;

pub use audience::resolve_resource_token_audience;
pub use keys::{Ed25519ResourceTokenSigner, ResourceTokenSigner};
pub use opaque::{InMemoryOpaqueAccessStore, OpaqueAccessStore};
pub use policy::{ResourceAccessMode, ResourceAccessPolicy};
pub use token::{ResourceTokenOptions, create_resource_token};
pub use verify::{
    VerifyResourceTokenOptions, VerifyTokenOptions, verify_resource_token, verify_token,
};
