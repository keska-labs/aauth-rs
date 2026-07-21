use aauth::signature::verify_request_signature;
use aauth::{create_key_provider, create_test_keys, mint_agent_jwt};
use aauth_reqwest::sign_request;

#[tokio::test]
async fn sign_request_verify_roundtrip() {
    let keys = create_test_keys();
    let agent_url = "http://127.0.0.1";
    let agent_jwt = mint_agent_jwt(&keys, agent_url, "aauth:test@example.com", None);
    let provider = create_key_provider(&keys, agent_jwt);
    let material = provider.key_material().await.unwrap();

    let url = format!("{agent_url}/api/data");
    let mut req = reqwest::Client::new().get(&url).build().unwrap();
    sign_request(&mut req, &material).unwrap();

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
