use std::sync::Arc;

use crate::deferred::{
    DeferRequirement, PendingInput, ServerPollOptions, ServerPollOutcome,
};
use crate::error::{MetadataError, Result};
use crate::protocol::{AccessServerMetadata, AccessTokenExchangeRequest, TokenResponseBody};

/// Wire outcome of a Person Server → Access Server token exchange (before auth-token verify).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AccessServerExchangeOutcome {
    Complete(TokenResponseBody),
    Deferred {
        requirement: DeferRequirement,
        as_pending_url: String,
    },
}

/// Outbound Access Server API used by a Person Server during federation.
///
/// Spec: `#ps-as-federation`, `#as-token-endpoint`, `#access-server-metadata`
#[trait_variant::make(AccessServerClient: Send)]
#[dynosaur::dynosaur(pub DynAccessServerClient = dyn(box) AccessServerClient, bridge(dyn))]
pub trait LocalAccessServerClient: Sync {
    /// Discover AS metadata at `{access_server_url}/.well-known/aauth-access.json`.
    async fn fetch_metadata(&self, access_server_url: &str) -> Result<AccessServerMetadata>;

    /// Signed POST to the AS token endpoint → grant or defer (402 stub as today).
    async fn exchange_token(
        &self,
        token_endpoint: &str,
        request: &AccessTokenExchangeRequest,
    ) -> Result<AccessServerExchangeOutcome>;

    /// Signed POST of agent input to an AS pending URL.
    async fn resume_pending(
        &self,
        pending_url: &str,
        input: &PendingInput,
    ) -> Result<Option<TokenResponseBody>>;

    /// GET-poll an AS pending URL (`Prefer: wait=…`, 503 backoff) to a terminal/re-defer outcome.
    async fn poll_pending(
        &self,
        access_server_url: &str,
        options: ServerPollOptions,
    ) -> Result<ServerPollOutcome>;
}

impl<T: AccessServerClient + Sync> AccessServerClient for Arc<T> {
    async fn fetch_metadata(&self, access_server_url: &str) -> Result<AccessServerMetadata> {
        (**self).fetch_metadata(access_server_url).await
    }

    async fn exchange_token(
        &self,
        token_endpoint: &str,
        request: &AccessTokenExchangeRequest,
    ) -> Result<AccessServerExchangeOutcome> {
        (**self).exchange_token(token_endpoint, request).await
    }

    async fn resume_pending(
        &self,
        pending_url: &str,
        input: &PendingInput,
    ) -> Result<Option<TokenResponseBody>> {
        (**self).resume_pending(pending_url, input).await
    }

    async fn poll_pending(
        &self,
        access_server_url: &str,
        options: ServerPollOptions,
    ) -> Result<ServerPollOutcome> {
        (**self).poll_pending(access_server_url, options).await
    }
}

impl<T: AccessServerClient + Sync> AccessServerClient for &T {
    async fn fetch_metadata(&self, access_server_url: &str) -> Result<AccessServerMetadata> {
        (**self).fetch_metadata(access_server_url).await
    }

    async fn exchange_token(
        &self,
        token_endpoint: &str,
        request: &AccessTokenExchangeRequest,
    ) -> Result<AccessServerExchangeOutcome> {
        (**self).exchange_token(token_endpoint, request).await
    }

    async fn resume_pending(
        &self,
        pending_url: &str,
        input: &PendingInput,
    ) -> Result<Option<TokenResponseBody>> {
        (**self).resume_pending(pending_url, input).await
    }

    async fn poll_pending(
        &self,
        access_server_url: &str,
        options: ServerPollOptions,
    ) -> Result<ServerPollOutcome> {
        (**self).poll_pending(access_server_url, options).await
    }
}

/// Placeholder [`AccessServerClient`] used as the default when federation is not configured.
///
/// Methods error if called. Use for three-party Person Servers that never federate, or replace
/// with a transport adapter (e.g. `aauth_reqwest::ReqwestAccessServerClient`).
#[derive(Clone, Copy, Debug, Default)]
pub struct AbsentAccessServerClient;

fn absent_error(op: &str) -> MetadataError {
    MetadataError::Request {
        url: format!("AbsentAccessServerClient::{op}"),
        source: Box::new(std::io::Error::new(
            std::io::ErrorKind::Unsupported,
            "no AccessServerClient configured",
        )),
    }
}

impl AccessServerClient for AbsentAccessServerClient {
    async fn fetch_metadata(&self, _access_server_url: &str) -> Result<AccessServerMetadata> {
        Err(absent_error("fetch_metadata").into())
    }

    async fn exchange_token(
        &self,
        _token_endpoint: &str,
        _request: &AccessTokenExchangeRequest,
    ) -> Result<AccessServerExchangeOutcome> {
        Err(absent_error("exchange_token").into())
    }

    async fn resume_pending(
        &self,
        _pending_url: &str,
        _input: &PendingInput,
    ) -> Result<Option<TokenResponseBody>> {
        Err(absent_error("resume_pending").into())
    }

    async fn poll_pending(
        &self,
        _access_server_url: &str,
        _options: ServerPollOptions,
    ) -> Result<ServerPollOutcome> {
        Err(absent_error("poll_pending").into())
    }
}
