# httpsig-key

Rust implementation of [HTTP Signature Keys](https://datatracker.ietf.org/doc/html/draft-hardt-httpbis-signature-key) — the `Signature-Key` header, Accept-Signature `sigkey`, and `Signature-Error` — on top of [`httpsig`](https://crates.io/crates/httpsig) (RFC 9421).

Used by [`aauth`](https://docs.rs/aauth) for the AAuth HTTP Message Signatures profile. You can depend on this crate alone if you only need Signature-Key sign/verify over `http::HeaderMap`.

**Pre-alpha.** First cut; APIs may change with the draft.

## Install

```toml
httpsig-key = { version = "0.0" }
```

## Spec

Canonical source of truth in this repo:

[`docs/specs/draft-hardt-httpbis-signature-key-05.txt`](https://github.com/keska-labs/aauth-rs/blob/main/docs/specs/draft-hardt-httpbis-signature-key-05.txt)

Public wire types cite draft sections via rustdoc `Spec:` lines.

## What is supported

- Sign and verify with `scheme=jwt` and `scheme=hwk` over request components (`method`, `authority`, `path`, covered headers)
- Parse/serialize [`SignatureKey`], [`SignatureErrorHeader`], and related SFV types in [`protocol`]
- JWK thumbprints via [`jwk_thumbprint`]

**Out of scope here:** JWT issuer trust and JWKS fetch. The application (e.g. `aauth`) resolves and validates the key material before or after cryptographic verify.

## Sign and verify

```rust
use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use http::HeaderMap;
use httpsig_key::protocol::{
    SignatureKey, SignatureKeyJwt, SigningJwk, SigningMaterial,
};
use httpsig_key::{SignOptions, VerifyOptions, sign, verify};

# fn main() {
let d = "XzLUZwwyJPTWtTaw_UNv-OdZF3UduhBrfXd3E419l0E";
let x = "qH0G403t91bvnfDz5vEkqb2Dt3daphQFV3pF7650Wfc";
let signing_jwk = SigningJwk {
    kty: "OKP".into(),
    crv: "Ed25519".into(),
    x: x.into(),
    y: None,
    d: d.into(),
    kid: None,
};
let public_jwk = signing_jwk.public_jwk();
let header = URL_SAFE_NO_PAD.encode(br#"{"alg":"none"}"#);
let payload = format!(
    r#"{{"cnf":{{"jwk":{{"kty":"{}","crv":"{}","x":"{}"}}}}}}"#,
    public_jwk.kty, public_jwk.crv, public_jwk.x
);
let jwt = format!("{header}.{}.", URL_SAFE_NO_PAD.encode(payload.as_bytes()));
let material = SigningMaterial {
    signing_jwk,
    signature_key: SignatureKey::Jwt(SignatureKeyJwt { jwt }),
};

let mut headers = HeaderMap::new();
sign(
    &mut headers,
    "GET",
    "resource.example",
    "/api",
    &material,
    &SignOptions::default(),
)
.unwrap();

let verified = verify(
    "GET",
    "resource.example",
    "/api",
    &headers,
    &VerifyOptions::default(),
)
.unwrap();
assert!(matches!(verified.signature_key, SignatureKey::Jwt(_)));
# }
```

[`VerifyOptions`] controls freshness (`max_age_secs`, `clock_skew_secs`), optional `Authorization` coverage, and signature label.

## See also

- RFC 9421 library: [`httpsig`](https://crates.io/crates/httpsig)
- AAuth (consumes this crate): [`aauth`](https://docs.rs/aauth)
