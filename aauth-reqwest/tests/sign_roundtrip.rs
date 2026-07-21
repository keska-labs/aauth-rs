use aauth::KeyMaterialProvider;
use aauth::SignatureError;
use aauth::TestKeys;
use aauth_reqwest::RequestSigningExt;
use httpsig_key::{VerifyOptions, verify};

#[tokio::test]
async fn sign_request_verify_roundtrip() {
    let keys = TestKeys::generate();
    let agent_url = "http://127.0.0.1";
    let agent_jwt = keys.mint_agent_jwt(agent_url, "aauth:test@example.com", None);
    let provider = keys.key_provider(agent_jwt);
    let material = provider.key_material().await.unwrap();

    let url = format!("{agent_url}/api/data");
    let mut req = reqwest::Client::new().get(&url).build().unwrap();
    req.sign(&material).unwrap();

    let headers = req.headers().clone();
    let verified = verify(
        req.method().as_str(),
        req.url().authority(),
        req.url().path(),
        &headers,
        &VerifyOptions::default(),
    )
    .unwrap();
    let _jwt = verified.jwt.ok_or(SignatureError::MissingJwtParam).unwrap();

    assert_eq!(verified.thumbprint, keys.agent_ephemeral.thumbprint());
}
