# Changelog

## Unreleased (v0.1.1)

### Changed

- A key-binding mismatch (`Request.JKT` set and the proof key thumbprint
  differs, `ErrThumbprint`) no longer returns `invalid_dpop_proof`:
  - at a resource server (`Request.AccessToken` set) it returns
    `invalid_token` with description "Invalid DPoP key binding"
    (RFC 9449 §7.1, Figure 16);
  - at a token endpoint (`Request.AccessToken` empty) it returns
    `invalid_grant`. RFC 9449 only requires rejection here; `invalid_grant`
    follows RFC 6749 §5.2 and is this library's interpretation.
- Proof-validity failures are unchanged and still return `invalid_dpop_proof`.

### Added

- `CodeInvalidToken` and `CodeInvalidGrant` constants.

## v0.1.0

- Initial release: RFC 9449 DPoP proof verification, RFC 7638 thumbprints,
  replay cache, nonce hook, typed errors, `WWW-Authenticate` helper,
  `dpoptest` proof builder.
