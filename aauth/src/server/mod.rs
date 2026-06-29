pub mod access;
pub mod person;
pub mod resource;

#[cfg(feature = "server-axum")]
pub mod axum;

pub use person::{InteractionManager, InteractionManagerOptions, PendingRequest};
pub use person::keys::{AuthJwtMinter, TestAuthJwtMinter, mint_auth_jwt};
pub use resource::keys::{Ed25519ResourceTokenSigner, ResourceTokenSigner};
pub use resource::{ResourceTokenOptions, VerifyTokenOptions, create_resource_token, verify_token};
