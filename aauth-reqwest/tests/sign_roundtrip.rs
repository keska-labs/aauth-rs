use aauth::KeyMaterialProvider;
use aauth::TestKeys;
use aauth::signature::verify_request_signature;
use aauth_reqwest::RequestSigningExt;

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
    let verified = verify_request_signature(
        req.method().as_str(),
        req.url().authority(),
        req.url().path(),
        &headers,
    )
    .unwrap();

    assert_eq!(verified.thumbprint, keys.agent_ephemeral.thumbprint());
}
