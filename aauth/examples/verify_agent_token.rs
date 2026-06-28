//! Verify an agent JWT using typed claims and a static JWKS fetcher.
//!
//! ```bash
//! cargo run --example verify_agent_token --features server
//! ```

use std::sync::Arc;

use aauth::{
    VerifiedToken, VerifyTokenOptions, create_test_keys, mint_agent_jwt,
    static_agent_metadata_fetcher, verify_token,
};

const AGENT_URL: &str = "https://agent.example";
const AGENT_ID: &str = "aauth:test@example.com";

#[tokio::main]
async fn main() -> aauth::Result<()> {
    let keys = create_test_keys();
    let agent_jwt = mint_agent_jwt(&keys, AGENT_URL, AGENT_ID);
    let fetcher = static_agent_metadata_fetcher(&keys, AGENT_URL);

    let verified = verify_token(VerifyTokenOptions {
        jwt: agent_jwt,
        http_signature_thumbprint: keys.agent_ephemeral.thumbprint().to_string(),
        fetcher: Arc::new(fetcher),
    })
    .await?;

    match verified {
        VerifiedToken::Agent(agent) => {
            println!("Token type: agent");
            println!("iss: {}", agent.iss);
            println!("sub: {}", agent.sub);
            println!("dwk: {}", agent.dwk);
            println!("jti: {}", agent.jti);
        }
        VerifiedToken::Auth(_) => {
            eprintln!("expected agent token");
            std::process::exit(1);
        }
    }

    Ok(())
}
