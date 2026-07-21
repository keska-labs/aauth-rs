//! Multi-party [`MetadataFetcher`] for local static JWKS (+ optional HTTP fallback).

use std::sync::Arc;

use aauth::TestKeys;
use aauth::metadata::{MetadataFetcher, StaticMetadataFetcher};
use async_trait::async_trait;

/// Routes well-known JWKS resolution by document type; optional HTTP for remote issuers.
#[derive(Clone)]
pub struct MultiPartyMetadataFetcher {
    agent: StaticMetadataFetcher,
    person: Option<StaticMetadataFetcher>,
    access: Option<StaticMetadataFetcher>,
    resource: StaticMetadataFetcher,
    agent_jwks_uri: String,
    person_jwks_uri: Option<String>,
    access_jwks_uri: Option<String>,
    resource_jwks_uri: String,
    http: Option<aauth_reqwest::CachedMetadataFetcher>,
}

impl MultiPartyMetadataFetcher {
    pub fn builder(
        keys: &TestKeys,
        agent_url: &str,
        resource_url: &str,
    ) -> MultiPartyMetadataFetcherBuilder {
        MultiPartyMetadataFetcherBuilder {
            keys: keys.clone(),
            agent_url: agent_url.to_string(),
            resource_url: resource_url.to_string(),
            person_server_url: None,
            access_server_url: None,
            with_http_fallback: false,
        }
    }
}

pub struct MultiPartyMetadataFetcherBuilder {
    keys: TestKeys,
    agent_url: String,
    resource_url: String,
    person_server_url: Option<String>,
    access_server_url: Option<String>,
    with_http_fallback: bool,
}

impl MultiPartyMetadataFetcherBuilder {
    pub fn person_server(mut self, url: impl Into<String>) -> Self {
        self.person_server_url = Some(url.into());
        self
    }

    pub fn access_server(mut self, url: impl Into<String>) -> Self {
        self.access_server_url = Some(url.into());
        self
    }

    /// Enable HTTP fetch for issuers not covered by local static JWKS (hybrid e2e).
    pub fn with_http_fallback(mut self) -> Self {
        self.with_http_fallback = true;
        self
    }

    pub fn build(self) -> Arc<dyn MetadataFetcher> {
        let agent_jwks_uri = format!("{}/jwks", self.agent_url.trim_end_matches('/'));
        let resource_jwks_uri = format!("{}/jwks", self.resource_url.trim_end_matches('/'));

        let person = self.person_server_url.as_ref().map(|url| {
            let jwks = format!("{}/auth/jwks", url.trim_end_matches('/'));
            (
                jwks.clone(),
                StaticMetadataFetcher::new(jwks, self.keys.person_server.jwk_set()),
            )
        });

        let access = self.access_server_url.as_ref().map(|url| {
            let jwks = format!("{}/access/jwks", url.trim_end_matches('/'));
            (
                jwks.clone(),
                StaticMetadataFetcher::new(jwks, self.keys.access_server.jwk_set()),
            )
        });

        let http = if self.with_http_fallback {
            Some(aauth_reqwest::CachedMetadataFetcher::new(
                reqwest::Client::new(),
            ))
        } else {
            None
        };

        Arc::new(MultiPartyMetadataFetcher {
            agent: StaticMetadataFetcher::new(
                agent_jwks_uri.clone(),
                self.keys.agent_root.jwk_set(),
            ),
            person: person.as_ref().map(|(_, f)| f.clone()),
            access: access.as_ref().map(|(_, f)| f.clone()),
            resource: StaticMetadataFetcher::new(
                resource_jwks_uri.clone(),
                self.keys.resource.jwk_set(),
            ),
            agent_jwks_uri,
            person_jwks_uri: person.map(|(u, _)| u),
            access_jwks_uri: access.map(|(u, _)| u),
            resource_jwks_uri,
            http,
        })
    }
}

#[async_trait]
impl MetadataFetcher for MultiPartyMetadataFetcher {
    async fn resolve_jwks_uri(&self, iss: &str, dwk: &str) -> aauth::Result<String> {
        match dwk {
            "aauth-agent.json" => self.agent.resolve_jwks_uri(iss, dwk).await,
            "aauth-person.json" => {
                if let Some(person) = &self.person {
                    person.resolve_jwks_uri(iss, dwk).await
                } else if let Some(http) = &self.http {
                    http.resolve_jwks_uri(iss, dwk).await
                } else {
                    Err(aauth::MetadataError::UnknownJwksUri(format!(
                        "no person JWKS configured for {iss}"
                    ))
                    .into())
                }
            }
            "aauth-access.json" => {
                if let Some(access) = &self.access {
                    access.resolve_jwks_uri(iss, dwk).await
                } else if let Some(http) = &self.http {
                    http.resolve_jwks_uri(iss, dwk).await
                } else {
                    Err(aauth::MetadataError::UnknownJwksUri(format!(
                        "no access JWKS configured for {iss}"
                    ))
                    .into())
                }
            }
            "aauth-resource.json" => self.resource.resolve_jwks_uri(iss, dwk).await,
            _ => {
                if let Some(http) = &self.http {
                    http.resolve_jwks_uri(iss, dwk).await
                } else {
                    Err(aauth::MetadataError::UnknownJwksUri(format!("unknown dwk: {dwk}")).into())
                }
            }
        }
    }

    async fn fetch_jwks(&self, jwks_uri: &str) -> aauth::Result<jsonwebtoken::jwk::JwkSet> {
        if jwks_uri == self.agent_jwks_uri {
            return self.agent.fetch_jwks(jwks_uri).await;
        }
        if jwks_uri == self.resource_jwks_uri {
            return self.resource.fetch_jwks(jwks_uri).await;
        }
        if self.person_jwks_uri.as_deref() == Some(jwks_uri) {
            return self
                .person
                .as_ref()
                .expect("person fetcher")
                .fetch_jwks(jwks_uri)
                .await;
        }
        if self.access_jwks_uri.as_deref() == Some(jwks_uri) {
            return self
                .access
                .as_ref()
                .expect("access fetcher")
                .fetch_jwks(jwks_uri)
                .await;
        }
        if let Some(http) = &self.http {
            return http.fetch_jwks(jwks_uri).await;
        }
        Err(aauth::MetadataError::UnknownJwksUri(jwks_uri.to_string()).into())
    }
}
