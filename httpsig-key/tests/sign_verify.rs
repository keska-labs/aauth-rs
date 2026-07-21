//! Sign/verify roundtrip and freshness tests.

use std::time::{SystemTime, UNIX_EPOCH};

use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use ed25519_dalek::SigningKey as Ed25519SigningKey;
use http::HeaderMap;
use httpsig_key::protocol::{
    PublicJwk, SIGNATURE_INPUT, SignatureKey, SignatureKeyHwk, SignatureKeyJwt, SigningJwk,
    SigningMaterial,
};
use httpsig_key::{Error, SignOptions, VerifyOptions, sign, verify};
use p256::ecdsa::SigningKey as EcdsaSigningKey;
use rand::Rng;
use rand::rand_core::UnwrapErr;
use rand::rngs::SysRng;

fn ed25519_material() -> SigningMaterial {
    let sk = Ed25519SigningKey::generate(&mut UnwrapErr(SysRng));
    let vk = sk.verifying_key();
    let d = URL_SAFE_NO_PAD.encode(sk.to_bytes());
    let x = URL_SAFE_NO_PAD.encode(vk.as_bytes());
    let signing_jwk = SigningJwk {
        kty: "OKP".into(),
        crv: "Ed25519".into(),
        x: x.clone(),
        y: None,
        d,
        kid: None,
    };
    let public_jwk = signing_jwk.public_jwk();
    let jwt = fake_jwt_with_cnf(&public_jwk);
    SigningMaterial {
        signing_jwk,
        signature_key: SignatureKey::Jwt(SignatureKeyJwt { jwt }),
    }
}

fn p256_material() -> SigningMaterial {
    let mut seed = [0u8; 32];
    // Loop until we get a valid scalar (extremely likely on first try).
    let sk = loop {
        UnwrapErr(SysRng).fill_bytes(&mut seed);
        if let Ok(sk) = EcdsaSigningKey::from_slice(&seed) {
            break sk;
        }
    };
    let vk = sk.verifying_key();
    let point = vk.to_encoded_point(false);
    let x = URL_SAFE_NO_PAD.encode(point.x().unwrap());
    let y = URL_SAFE_NO_PAD.encode(point.y().unwrap());
    let d = URL_SAFE_NO_PAD.encode(sk.to_bytes());
    let signing_jwk = SigningJwk {
        kty: "EC".into(),
        crv: "P-256".into(),
        x,
        y: Some(y),
        d,
        kid: None,
    };
    let public_jwk = signing_jwk.public_jwk();
    SigningMaterial {
        signing_jwk,
        signature_key: SignatureKey::Hwk(SignatureKeyHwk { jwk: public_jwk }),
    }
}

fn fake_jwt_with_cnf(jwk: &PublicJwk) -> String {
    let header = URL_SAFE_NO_PAD.encode(br#"{"alg":"none"}"#);
    let payload = format!(
        r#"{{"cnf":{{"jwk":{{"kty":"{}","crv":"{}","x":"{}"}}}}}}"#,
        jwk.kty, jwk.crv, jwk.x
    );
    let payload_b64 = URL_SAFE_NO_PAD.encode(payload.as_bytes());
    format!("{header}.{payload_b64}.")
}

#[test]
fn ed25519_jwt_sign_verify_roundtrip() {
    let material = ed25519_material();
    let mut headers = HeaderMap::new();
    sign(
        &mut headers,
        "GET",
        "example.com",
        "/resource",
        &material,
        &SignOptions::default(),
    )
    .unwrap();

    let verified = verify(
        "GET",
        "example.com",
        "/resource",
        &headers,
        &VerifyOptions::default(),
    )
    .unwrap();
    assert!(verified.jwt.is_some());
    assert!(!verified.thumbprint.is_empty());
}

#[test]
fn p256_hwk_sign_verify_roundtrip() {
    let material = p256_material();
    let mut headers = HeaderMap::new();
    sign(
        &mut headers,
        "POST",
        "api.example.com",
        "/v1/items",
        &material,
        &SignOptions::default(),
    )
    .unwrap();

    let verified = verify(
        "POST",
        "api.example.com",
        "/v1/items",
        &headers,
        &VerifyOptions::default(),
    )
    .unwrap();
    assert!(verified.jwt.is_none());
    match verified.signature_key {
        SignatureKey::Hwk(_) => {}
        other => panic!("expected hwk, got {other:?}"),
    }
}

#[test]
fn rejects_stale_created() {
    let material = ed25519_material();
    let mut headers = HeaderMap::new();
    sign(
        &mut headers,
        "GET",
        "example.com",
        "/",
        &material,
        &SignOptions::default(),
    )
    .unwrap();

    let input = headers.get(&SIGNATURE_INPUT).unwrap().to_str().unwrap();
    let stale = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs()
        - 10_000;
    let rewritten = rewrite_created(input, stale);
    headers.insert(
        SIGNATURE_INPUT,
        http::HeaderValue::from_str(&rewritten).unwrap(),
    );

    let err = verify(
        "GET",
        "example.com",
        "/",
        &headers,
        &VerifyOptions {
            max_age_secs: 60,
            clock_skew_secs: 0,
            ..Default::default()
        },
    )
    .unwrap_err();
    assert!(
        matches!(err, Error::Expired),
        "expected Expired, got {err:?}"
    );
}

fn rewrite_created(signature_input: &str, created: u64) -> String {
    let mut out = String::new();
    let mut parts = signature_input.split(';');
    if let Some(first) = parts.next() {
        out.push_str(first);
    }
    let mut saw_created = false;
    for part in parts {
        out.push(';');
        if part.trim().starts_with("created=") {
            out.push_str(&format!("created={created}"));
            saw_created = true;
        } else {
            out.push_str(part);
        }
    }
    assert!(saw_created, "created param missing in {signature_input}");
    out
}
