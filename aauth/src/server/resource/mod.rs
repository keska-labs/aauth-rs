pub mod keys;

#[cfg(feature = "server-axum")]
pub mod axum;

mod token;
mod verify;

pub use keys::{Ed25519ResourceTokenSigner, ResourceTokenSigner};
pub use token::{ResourceTokenOptions, create_resource_token};
pub use verify::{VerifyTokenOptions, verify_token};
