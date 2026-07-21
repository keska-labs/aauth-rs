//! One-hop axum app definers for integration tests.

#![allow(unused_imports)]

pub mod common;
pub mod federated;
pub mod identity;
pub mod person;
pub mod resource_managed;

pub use federated::{
    AccessPolicyKind, AccessServerParts, FederatedPersonServerParts, access_server_app,
    federated_person_server_app, federated_resource_app,
};
pub use identity::identity_resource_app;
pub use person::{
    PersonPolicyKind, PersonServerParts, hosted_person_managed_resource_app,
    person_managed_resource_app, person_server_app,
};
pub use resource_managed::{ResourceManagedParts, ResourcePolicyKind, resource_managed_app};
