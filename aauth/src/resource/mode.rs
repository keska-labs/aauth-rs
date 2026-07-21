use crate::resource::no_service::NoResourceAccessService;
use crate::resource::service::ResourceAccessService;

/// How a resource server evaluates access for incoming agent requests.
#[derive(Clone)]
pub enum ResourceAccessMode<S = NoResourceAccessService>
where
    S: ResourceAccessService,
{
    /// Grant based on verified agent or auth token identity alone.
    IdentityBased,
    /// Delegate authorization to the agent's Person Server (or Access Server when federated).
    PsAsserted {
        require_auth_token: bool,
        access_server_url: Option<String>,
        person_server_fallback: Option<String>,
    },
    /// Resource manages authorization via interaction and opaque access tokens.
    ResourceManaged { service: S },
}
