# dpop

[![CI](https://github.com/authfly/dpop/actions/workflows/ci.yml/badge.svg?branch=main)](https://github.com/authfly/dpop/actions/workflows/ci.yml)

Server-side verification of OAuth 2.0 DPoP proofs ([RFC 9449]) for Go.

`github.com/authfly/dpop` checks a `DPoP` proof JWT against the HTTP request it
arrived with and returns the key thumbprint (`jkt`, [RFC 7638]) to bind tokens
to. It is meant for an authorization server token endpoint and for resource
servers. It does not issue tokens and keeps no token state.

> **Status: experimental, not audited.** The API may change before v1.0.
> Do not rely on it as your only defence until it has had an independent review.

Dependencies: the Go standard library and [go-jose/v4].

## Install

```sh
go get github.com/authfly/dpop
```

Requires Go 1.26 or newer.

## Usage

### Token endpoint

```go
verifier, err := dpop.NewVerifier(dpop.Config{
	Replay: dpop.NewMemoryReplayCache(0), // use a shared cache with several instances
})

func token(w http.ResponseWriter, r *http.Request) {
	proof, err := dpop.ProofFromHeader(r.Header)
	if err == nil {
		var p *dpop.Proof
		p, err = verifier.Verify(r.Context(), proof, dpop.Request{
			Method: r.Method,
			URL:    "https://as.example.com/oauth/token", // public URL of this endpoint
		})
		if err == nil {
			// Issue tokens bound to p.JKT: cnf.jkt in a JWT access token or in
			// introspection, token_type "DPoP", and bind refresh tokens of public
			// clients to p.JKT as well.
			_ = p
		}
	}
	if err != nil {
		// 400 {"error": dpop.Code(err)} -> invalid_dpop_proof or use_dpop_nonce
	}
}
```

For a refresh token or an authorization code bound with `dpop_jkt`, set
`Request.JKT` to the stored thumbprint.

### Resource server

```go
p, err := verifier.Verify(ctx, proof, dpop.Request{
	Method:      r.Method,
	URL:         publicURL,      // scheme://host/path as the client sees it
	AccessToken: accessToken,    // from "Authorization: DPoP <token>"; requires ath
	JKT:         tokenCnfJKT,    // cnf.jkt from the token or introspection
})
if err != nil {
	w.Header().Set("WWW-Authenticate",
		dpop.WWWAuthenticate(verifier.Algorithms(), dpop.Code(err), "invalid DPoP proof"))
	w.WriteHeader(http.StatusUnauthorized)
	return
}
```

### Server nonces

Set `Config.Nonces` to a `dpop.NonceSource` to require server-provided nonces.
A missing or rejected nonce returns an error with code `use_dpop_nonce`; send a
fresh nonce with `dpop.SetNonce(w.Header(), nonce)`. Nonce generation and
rotation are up to the implementation.

## What is checked

Following RFC 9449 §4.3 (and §7.1 for resource servers):

- exactly one `DPoP` header, a JWS compact serialization of at most 8 KiB;
- `typ` is exactly `dpop+jwt`; no `crit`;
- `alg` is in the allowlist: `ES256` and `EdDSA` by default, `ES384` optional;
  `none`, HMAC and RSA are rejected;
- `jwk` is an EC (P-256/P-384) or Ed25519 public key that matches `alg`;
  private or symmetric key members are rejected;
- the signature verifies with that key;
- `jti`, `htm`, `htu`, `iat` are present; `htm` equals the request method;
  `htu` equals the request URI after normalization (query and fragment
  removed, scheme and host lower-cased, default port dropped,
  percent-encoding normalized);
- `iat` is within `[now - MaxAge, now + Leeway]` (defaults 2 min and 5 s);
- `ath` matches the access token, when one is given;
- the key thumbprint matches the expected `jkt`, when one is given;
- the nonce is valid, when a `NonceSource` is configured;
- the (`jkt`, `jti`) pair was not seen before. A `ReplayCache` is required
  unless replay checking is explicitly disabled. Cache errors fail closed.

## Threat notes

- **Replay across instances.** `MemoryReplayCache` protects one process. Behind
  a load balancer use a shared `ReplayCache` (for example Redis `SET NX` with an
  expiry), or replayed proofs may be accepted by another instance within the
  `iat` window.
- **Request URL.** Pass the URL the client used. Behind a proxy, build it from
  configuration, not from `Host` or `X-Forwarded-*` headers supplied by the
  client.
- **Pre-generated proofs.** Without nonces, a client that is compromised for a
  short time can mint proofs dated in the future, limited by `Leeway`. Server
  nonces (RFC 9449 §11.2) close this gap.
- **Stolen keys.** DPoP binds tokens to a key; it does not help if the private
  key itself is exfiltrated. Use non-extractable keys on the client side.
- **Clock.** `iat` checks depend on the server clock. Keep it synchronized.
- **Not covered here:** token issuance, `cnf` claims, introspection, metadata
  (`dpop_signing_alg_values_supported`), and client-side key storage.

## Testing helpers

Package `github.com/authfly/dpop/dpoptest` creates proofs (including malformed
ones) for tests. It is not a production client.

## Supply chain

CI runs `go vet`, `go test -race`, staticcheck, govulncheck and short fuzzing
on every push. Tagged releases (`v*`) publish a source archive and `SHA256SUMS`
with SLSA build provenance generated by GitHub Actions. Verify with:

```sh
gh attestation verify dpop-vX.Y.Z.tar.gz --repo authfly/dpop
```

## License

Apache License 2.0. Copyright 2026 Authfly.

[RFC 9449]: https://www.rfc-editor.org/rfc/rfc9449
[RFC 7638]: https://www.rfc-editor.org/rfc/rfc7638
[go-jose/v4]: https://github.com/go-jose/go-jose
