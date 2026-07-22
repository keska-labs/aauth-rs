use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
use ed25519_dalek::pkcs8::EncodePrivateKey;
use ed25519_dalek::SigningKey as DalekSigningKey;
use jsonwebtoken::{Algorithm, EncodingKey, Header, encode};
use p256::ecdsa::SigningKey as P256SigningKey;
use p256::elliptic_curve::rand_core::OsRng;
use p256::pkcs8::EncodePrivateKey as _;
use rand::rand_core::UnwrapErr;
use rand::rngs::SysRng;
use serde_json::{json, Value};
use uuid::Uuid;

use crate::backends::{
    algorithm_from_jwk, hardware_sign, strip_private, value_to_signing_jwk,
};
use crate::config::get_agent_config;
use crate::error::{Error, Result};
use crate::keychain::read_keychain;
use crate::resolve::resolve_key;
use crate::types::{
    AgentTokenResult, KeyAlgorithm, KeyBackend, SignAgentTokenOptions, SignatureKeyJwt,
};

/// Sign an agent token for the given agent URL (resolves key automatically).
pub async fn sign_agent_token(options: SignAgentTokenOptions) -> Result<AgentTokenResult> {
    let agent_config = get_agent_config(&options.agent_url);
    let person_server_url = options
        .person_server_url
        .clone()
        .or_else(|| agent_config.and_then(|c| c.person_server_url));

    let resolved = resolve_key(&options.agent_url).await?;
    let lifetime = options.lifetime.unwrap_or(3600);

    if resolved.backend == KeyBackend::Software {
        return sign_with_software_key(
            &options.agent_url,
            &options.sub,
            lifetime,
            &resolved.kid,
            person_server_url.as_deref(),
        );
    }

    sign_with_hardware_key(
        &resolved,
        &options.agent_url,
        &options.sub,
        lifetime,
        person_server_url.as_deref(),
    )
}

fn sign_with_software_key(
    agent_url: &str,
    sub: &str,
    lifetime: u64,
    kid: &str,
    person_server_url: Option<&str>,
) -> Result<AgentTokenResult> {
    let data = read_keychain(agent_url)?
        .ok_or_else(|| Error::msg(format!("No software keys in keychain for {agent_url}")))?;

    let root_jwk = data
        .keys
        .get(kid)
        .or_else(|| data.keys.get(&data.current))
        .ok_or_else(|| Error::msg(format!("Key {kid} not found in keychain for {agent_url}")))?;

    let actual_kid = root_jwk
        .get("kid")
        .and_then(|v| v.as_str())
        .unwrap_or(kid);
    let alg = algorithm_from_jwk(root_jwk)
        .ok_or_else(|| Error::msg("Could not determine software key algorithm"))?;

    let (eph_priv, eph_pub) = generate_ephemeral(alg)?;
    let encoding_key = encoding_key_from_jwk(root_jwk, alg)?;

    let now = now_secs();
    let mut claims = json!({
        "iss": agent_url,
        "dwk": "aauth-agent.json",
        "sub": sub,
        "jti": Uuid::new_v4().to_string(),
        "cnf": { "jwk": eph_pub },
        "iat": now,
        "exp": now + lifetime as i64,
    });
    if let Some(ps) = person_server_url {
        claims["ps"] = Value::String(ps.to_string());
    }

    let mut header = Header::new(match alg {
        KeyAlgorithm::EdDSA => Algorithm::EdDSA,
        KeyAlgorithm::ES256 => Algorithm::ES256,
        KeyAlgorithm::RS256 => Algorithm::RS256,
    });
    header.typ = Some("aa-agent+jwt".into());
    header.kid = Some(actual_kid.to_string());

    let jwt = encode(&header, &claims, &encoding_key).map_err(|e| Error::Jwt(e.to_string()))?;

    Ok(AgentTokenResult {
        signing_key: eph_priv,
        signature_key: SignatureKeyJwt::new(jwt),
    })
}

fn sign_with_hardware_key(
    resolved: &crate::types::ResolvedKey,
    agent_url: &str,
    sub: &str,
    lifetime: u64,
    person_server_url: Option<&str>,
) -> Result<AgentTokenResult> {
    let eph_alg = if resolved.algorithm == KeyAlgorithm::RS256 {
        KeyAlgorithm::ES256
    } else {
        resolved.algorithm
    };
    let (eph_priv, eph_pub) = generate_ephemeral(eph_alg)?;

    let now = now_secs();
    let header = json!({
        "alg": resolved.algorithm.as_str(),
        "typ": "aa-agent+jwt",
        "kid": resolved.kid,
    });
    let mut payload = json!({
        "iss": agent_url,
        "dwk": "aauth-agent.json",
        "sub": sub,
        "jti": Uuid::new_v4().to_string(),
        "cnf": { "jwk": eph_pub },
        "iat": now,
        "exp": now + lifetime as i64,
    });
    if let Some(ps) = person_server_url {
        payload["ps"] = Value::String(ps.to_string());
    }

    let header_b64 = URL_SAFE_NO_PAD.encode(serde_json::to_vec(&header)?);
    let payload_b64 = URL_SAFE_NO_PAD.encode(serde_json::to_vec(&payload)?);
    let signing_input = format!("{header_b64}.{payload_b64}");

    let signature = hardware_sign(resolved.backend, &resolved.key_id, signing_input.as_bytes())?;
    let sig_b64 = URL_SAFE_NO_PAD.encode(signature);
    let jwt = format!("{signing_input}.{sig_b64}");

    Ok(AgentTokenResult {
        signing_key: eph_priv,
        signature_key: SignatureKeyJwt::new(jwt),
    })
}

fn generate_ephemeral(alg: KeyAlgorithm) -> Result<(Value, Value)> {
    match alg {
        KeyAlgorithm::EdDSA | KeyAlgorithm::RS256 => {
            // RS256 roots use ES256 ephemeral (matches JS).
            if alg == KeyAlgorithm::RS256 {
                return generate_ephemeral(KeyAlgorithm::ES256);
            }
            let signing_key = DalekSigningKey::generate(&mut UnwrapErr(SysRng));
            let verifying = signing_key.verifying_key();
            let priv_jwk = json!({
                "kty": "OKP",
                "crv": "Ed25519",
                "x": URL_SAFE_NO_PAD.encode(verifying.as_bytes()),
                "d": URL_SAFE_NO_PAD.encode(signing_key.to_bytes()),
            });
            let pub_jwk = strip_private(&priv_jwk);
            Ok((priv_jwk, pub_jwk))
        }
        KeyAlgorithm::ES256 => {
            let signing_key = P256SigningKey::random(&mut OsRng);
            let verifying = signing_key.verifying_key();
            let point = verifying.to_encoded_point(false);
            let x = point.x().ok_or_else(|| Error::msg("P-256 missing x"))?;
            let y = point.y().ok_or_else(|| Error::msg("P-256 missing y"))?;
            let priv_jwk = json!({
                "kty": "EC",
                "crv": "P-256",
                "x": URL_SAFE_NO_PAD.encode(x),
                "y": URL_SAFE_NO_PAD.encode(y),
                "d": URL_SAFE_NO_PAD.encode(signing_key.to_bytes()),
            });
            let pub_jwk = strip_private(&priv_jwk);
            Ok((priv_jwk, pub_jwk))
        }
    }
}

fn encoding_key_from_jwk(jwk: &Value, alg: KeyAlgorithm) -> Result<EncodingKey> {
    let signing = value_to_signing_jwk(jwk)?;
    match alg {
        KeyAlgorithm::EdDSA => {
            let d = URL_SAFE_NO_PAD
                .decode(signing.d.as_bytes())
                .map_err(|e| Error::Jwt(e.to_string()))?;
            let bytes: [u8; 32] = d
                .try_into()
                .map_err(|_| Error::Jwt("Ed25519 d must be 32 bytes".into()))?;
            let sk = DalekSigningKey::from_bytes(&bytes);
            let der = sk
                .to_pkcs8_der()
                .map_err(|e| Error::Jwt(e.to_string()))?;
            Ok(EncodingKey::from_ed_der(der.as_bytes()))
        }
        KeyAlgorithm::ES256 => {
            let d = URL_SAFE_NO_PAD
                .decode(signing.d.as_bytes())
                .map_err(|e| Error::Jwt(e.to_string()))?;
            let sk = P256SigningKey::from_slice(&d).map_err(|e| Error::Jwt(e.to_string()))?;
            let der = sk
                .to_pkcs8_der()
                .map_err(|e| Error::Jwt(e.to_string()))?;
            Ok(EncodingKey::from_ec_der(der.as_bytes()))
        }
        KeyAlgorithm::RS256 => Err(Error::msg(
            "Software backend does not support RS256 root keys",
        )),
    }
}

fn now_secs() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0)
}