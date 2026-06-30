use crate::deferred::OutboundSignatureProvider;
use crate::jwt::OkpSigningJwk;
use crate::keys::TestKeys;
use crate::person_server::keys::mint_person_server_signature_jwt;

/// Person Server outbound signer for federation pending POST/poll to an Access Server.
#[derive(Clone)]
pub struct PersonServerOutboundSigner {
    pub person_server_url: String,
    pub signing_jwk: OkpSigningJwk,
    pub keys: TestKeys,
}

impl OutboundSignatureProvider for PersonServerOutboundSigner {
    fn signature_jwt(&self) -> String {
        mint_person_server_signature_jwt(&self.keys, &self.person_server_url)
    }

    fn signing_jwk(&self) -> &OkpSigningJwk {
        &self.signing_jwk
    }
}
