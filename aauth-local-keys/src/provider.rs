use std::sync::Arc;

use aauth::KeyMaterialProvider;
use httpsig_key::{SignatureKey, SignatureKeyJwt, SigningMaterial};

use crate::backends::value_to_signing_jwk;
use crate::create_agent_token::{create_agent_token, CreateAgentTokenOptions};
use crate::error::Result;

/// [`KeyMaterialProvider`] that loads keys like `@aauth/local-keys`.
#[derive(Clone, Debug, Default)]
pub struct LocalKeysProvider {
    options: CreateAgentTokenOptions,
}

impl LocalKeysProvider {
    pub fn builder() -> LocalKeysProviderBuilder {
        LocalKeysProviderBuilder::default()
    }

    pub fn new(options: CreateAgentTokenOptions) -> Self {
        Self { options }
    }

    pub fn into_arc(self) -> Arc<Self> {
        Arc::new(self)
    }
}

#[derive(Clone, Debug, Default)]
pub struct LocalKeysProviderBuilder {
    options: CreateAgentTokenOptions,
}

impl LocalKeysProviderBuilder {
    pub fn agent_url(mut self, url: impl Into<String>) -> Self {
        self.options.agent_url = Some(url.into());
        self
    }

    pub fn agent_id(mut self, id: impl Into<String>) -> Self {
        self.options.agent_id = Some(id.into());
        self
    }

    pub fn local(mut self, local: impl Into<String>) -> Self {
        self.options.local = Some(local.into());
        self
    }

    pub fn token_lifetime(mut self, secs: u64) -> Self {
        self.options.token_lifetime = Some(secs);
        self
    }

    pub fn person_server_url(mut self, url: impl Into<String>) -> Self {
        self.options.person_server_url = Some(url.into());
        self
    }

    pub fn build(self) -> LocalKeysProvider {
        LocalKeysProvider::new(self.options)
    }
}

impl KeyMaterialProvider for LocalKeysProvider {
    async fn key_material(&self) -> aauth::Result<SigningMaterial> {
        load_material(self.options.clone())
            .await
            .map_err(aauth::AAuthError::from)
    }
}

async fn load_material(options: CreateAgentTokenOptions) -> Result<SigningMaterial> {
    let token = create_agent_token(options).await?;
    let signing_jwk = value_to_signing_jwk(&token.signing_key)?;
    Ok(SigningMaterial {
        signing_jwk,
        signature_key: SignatureKey::Jwt(SignatureKeyJwt {
            jwt: token.signature_key.jwt,
        }),
    })
}
