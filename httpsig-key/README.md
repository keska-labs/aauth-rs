# httpsig-key

Rust implementation of [HTTP Signature Keys](https://datatracker.ietf.org/doc/html/draft-hardt-httpbis-signature-key)
(`Signature-Key`, Accept-Signature `sigkey`, `Signature-Error`) on top of
[`httpsig`](https://crates.io/crates/httpsig) (RFC 9421).

## Spec

Canonical source of truth:

[`docs/specs/draft-hardt-httpbis-signature-key-05.txt`](../docs/specs/draft-hardt-httpbis-signature-key-05.txt)

Public wire types cite draft sections via rustdoc `Spec:` lines (same pattern as `aauth`).

## Status

Pre-alpha. First cut supports `scheme=jwt` and `scheme=hwk` for sign/verify over
`http::HeaderMap` + derived components. JWT *issuer* trust (JWKS fetch) stays in
the application (e.g. `aauth`).
