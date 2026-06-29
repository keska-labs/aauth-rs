use std::sync::{Arc, Mutex};

use crate::server::interaction::InteractionManager;
use crate::server::resource::opaque::OpaqueAccessStore;

/// How a resource server evaluates access for incoming agent requests.
#[derive(Clone)]
pub enum ResourceAccessPolicy {
    /// Grant based on verified agent or auth token identity alone.
    IdentityBased,
    /// Delegate authorization to the agent's Person Server (or Access Server when federated).
    PsAsserted {
        require_auth_token: bool,
        access_server_url: Option<String>,
        person_server_fallback: Option<String>,
    },
    /// Resource manages authorization via interaction and opaque access tokens.
    ResourceManaged {
        interaction_manager: Arc<InteractionManager>,
        opaque_store: Arc<dyn OpaqueAccessStore>,
        pending_id_capture: Option<Arc<Mutex<Option<String>>>>,
    },
}
