// Copyright 2026 Authfly
// SPDX-License-Identifier: Apache-2.0

package dpop

import (
	"bytes"
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"math"
	"net/http"
	"strings"
	"time"

	jose "github.com/go-jose/go-jose/v4"
)

// HeaderName is the request header that carries the proof (RFC 9449 §4.1).
const HeaderName = "DPoP"

// ProofType is the required value of the JOSE typ header (RFC 9449 §4.2).
const ProofType = "dpop+jwt"

// Supported JWS algorithms. Symmetric algorithms and "none" are never
// accepted.
const (
	ES256 = "ES256"
	ES384 = "ES384"
	EdDSA = "EdDSA"
)

// DefaultAlgorithms is used when Config.Algorithms is empty.
var DefaultAlgorithms = []string{ES256, EdDSA}

// Defaults for Config.
const (
	DefaultMaxAge       = 2 * time.Minute
	DefaultLeeway       = 5 * time.Second
	DefaultMaxProofSize = 8 << 10
	maxIDLength         = 256
)

// Config configures a Verifier.
type Config struct {
	// Algorithms allowed in the proof alg header. Each must be ES256,
	// ES384 or EdDSA. Empty selects DefaultAlgorithms.
	Algorithms []string
	// MaxAge is how far in the past iat may be. Zero selects DefaultMaxAge.
	MaxAge time.Duration
	// Leeway is how far in the future iat may be (clock skew). Zero
	// selects DefaultLeeway; use a negative value for no leeway.
	Leeway time.Duration
	// Replay records proof identifiers. Required unless
	// DisableReplayCheck is set.
	Replay ReplayCache
	// DisableReplayCheck turns off jti replay detection. Only for
	// deployments that enforce single use another way (for example
	// server nonces bound to one request).
	DisableReplayCheck bool
	// Nonces, when set, makes a valid server nonce mandatory.
	Nonces NonceSource
	// MaxProofSize bounds the proof length in bytes. Zero selects
	// DefaultMaxProofSize.
	MaxProofSize int
	// Now returns the current time. Nil selects time.Now.
	Now func() time.Time
}

// Verifier checks DPoP proofs. It is safe for concurrent use.
type Verifier struct {
	algs    []jose.SignatureAlgorithm
	maxAge  time.Duration
	leeway  time.Duration
	replay  ReplayCache
	nonces  NonceSource
	maxSize int
	now     func() time.Time
}

// NewVerifier validates cfg and returns a Verifier.
func NewVerifier(cfg Config) (*Verifier, error) {
	v := &Verifier{
		maxAge:  cfg.MaxAge,
		leeway:  cfg.Leeway,
		replay:  cfg.Replay,
		nonces:  cfg.Nonces,
		maxSize: cfg.MaxProofSize,
		now:     cfg.Now,
	}
	algs := cfg.Algorithms
	if len(algs) == 0 {
		algs = DefaultAlgorithms
	}
	for _, a := range algs {
		switch a {
		case ES256, ES384, EdDSA:
			v.algs = append(v.algs, jose.SignatureAlgorithm(a))
		default:
			return nil, fmt.Errorf("dpop: algorithm %q not supported", a)
		}
	}
	if v.maxAge == 0 {
		v.maxAge = DefaultMaxAge
	}
	if v.maxAge < 0 {
		return nil, errors.New("dpop: MaxAge must be positive")
	}
	if v.leeway == 0 {
		v.leeway = DefaultLeeway
	} else if v.leeway < 0 {
		v.leeway = 0
	}
	if v.maxSize <= 0 {
		v.maxSize = DefaultMaxProofSize
	}
	if v.now == nil {
		v.now = time.Now
	}
	if v.replay == nil && !cfg.DisableReplayCheck {
		return nil, errors.New("dpop: Replay is required (or set DisableReplayCheck)")
	}
	return v, nil
}

// Algorithms returns the accepted algorithms, e.g. for the algs parameter of
// WWW-Authenticate or dpop_signing_alg_values_supported in metadata.
func (v *Verifier) Algorithms() []string {
	out := make([]string, len(v.algs))
	for i, a := range v.algs {
		out[i] = string(a)
	}
	return out
}

// Request describes the HTTP request a proof is checked against.
type Request struct {
	// Method is the HTTP method, compared case-sensitively with htm.
	Method string
	// URL is the absolute request URI as seen by the client (scheme and
	// host of the public endpoint, not of an internal listener). Query
	// and fragment are ignored.
	URL string
	// AccessToken, when non-empty, requires an ath claim equal to
	// AccessTokenHash(AccessToken). Set it at resource servers.
	AccessToken string
	// JKT, when non-empty, requires the proof key thumbprint to equal it
	// (the cnf.jkt of a bound token, or dpop_jkt from an authorization
	// request).
	JKT string
}

// Proof is a verified DPoP proof.
type Proof struct {
	Algorithm       string
	PublicKey       crypto.PublicKey
	JKT             string // base64url SHA-256 JWK thumbprint (RFC 7638)
	ID              string // jti
	Method          string // htm
	URI             string // htu as sent
	IssuedAt        time.Time
	Nonce           string
	AccessTokenHash string // ath, if present
}

// ProofFromHeader returns the single DPoP header value. A missing header or
// more than one value is an error (RFC 9449 §4.3).
func ProofFromHeader(h http.Header) (string, error) {
	vals := h.Values(HeaderName)
	switch {
	case len(vals) == 0 || (len(vals) == 1 && strings.TrimSpace(vals[0]) == ""):
		return "", invalid(ErrMissing, "DPoP proof missing")
	case len(vals) > 1 || strings.Contains(vals[0], ","):
		return "", invalid(ErrMultiple, "more than one DPoP proof")
	}
	return strings.TrimSpace(vals[0]), nil
}

// AccessTokenHash returns the ath value for token: base64url(SHA-256(token)).
func AccessTokenHash(token string) string {
	sum := sha256.Sum256([]byte(token))
	return base64.RawURLEncoding.EncodeToString(sum[:])
}

// Thumbprint returns the base64url-encoded JWK SHA-256 thumbprint of pub as
// defined in RFC 7638 (the jkt value of RFC 9449 §6.1).
func Thumbprint(pub crypto.PublicKey) (string, error) {
	jwk := jose.JSONWebKey{Key: pub}
	if !jwk.IsPublic() {
		return "", errors.New("dpop: thumbprint requires a public key")
	}
	sum, err := jwk.Thumbprint(crypto.SHA256)
	if err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(sum), nil
}

type claims struct {
	JTI   string          `json:"jti"`
	HTM   string          `json:"htm"`
	HTU   string          `json:"htu"`
	IAT   json.RawMessage `json:"iat"`
	Nonce string          `json:"nonce"`
	ATH   string          `json:"ath"`
}

// Verify checks proof against r and returns the verified proof. Proof
// failures are of type *Error; use Code to get the OAuth error code. An
// unparsable r.URL is a server configuration error and is returned as a plain
// error.
//
// Checks follow RFC 9449 §4.3 (and §7.1 at resource servers): single
// well-formed JWS compact JWT, typ dpop+jwt, allowed asymmetric alg, public
// embedded jwk matching alg, valid signature, jti/htm/htu/iat present, htm
// and htu match, iat within [now-MaxAge, now+Leeway], ath and jkt when
// required, nonce when a NonceSource is set, and jti not seen before.
func (v *Verifier) Verify(ctx context.Context, proof string, r Request) (*Proof, error) {
	if proof == "" {
		return nil, invalid(ErrMissing, "DPoP proof missing")
	}
	if len(proof) > v.maxSize {
		return nil, invalid(ErrMalformed, "DPoP proof too large")
	}
	if err := v.checkHeader(proof); err != nil {
		return nil, err
	}
	jws, err := jose.ParseSignedCompact(proof, v.algs)
	if err != nil {
		return nil, invalid(ErrMalformed, "DPoP proof malformed")
	}
	if len(jws.Signatures) != 1 {
		return nil, invalid(ErrMalformed, "DPoP proof malformed")
	}
	hdr := jws.Signatures[0].Protected
	alg := hdr.Algorithm
	if hdr.JSONWebKey == nil {
		return nil, invalid(ErrKey, "DPoP proof jwk missing")
	}
	pub, err := checkKey(alg, hdr.JSONWebKey)
	if err != nil {
		return nil, err
	}
	payload, err := jws.Verify(pub)
	if err != nil {
		return nil, invalid(ErrSignature, "DPoP proof signature invalid")
	}

	var c claims
	dec := json.NewDecoder(bytes.NewReader(payload))
	dec.UseNumber()
	if err := dec.Decode(&c); err != nil || dec.More() {
		return nil, invalid(ErrMalformed, "DPoP proof claims malformed")
	}
	if c.JTI == "" || len(c.JTI) > maxIDLength || c.HTM == "" || c.HTU == "" || len(c.IAT) == 0 {
		return nil, invalid(ErrMalformed, "DPoP proof missing required claims")
	}
	if c.HTM != r.Method {
		return nil, invalid(ErrMethod, "DPoP proof htm mismatch")
	}
	want, err := NormalizeURI(r.URL)
	if err != nil {
		return nil, fmt.Errorf("dpop: invalid request URL: %w", err)
	}
	got, err := NormalizeURI(c.HTU)
	if err != nil || got != want {
		return nil, invalid(ErrURI, "DPoP proof htu mismatch")
	}
	iat, err := numericDate(c.IAT)
	if err != nil {
		return nil, invalid(ErrMalformed, "DPoP proof iat malformed")
	}
	now := v.now()
	if iat.Before(now.Add(-v.maxAge)) || iat.After(now.Add(v.leeway)) {
		return nil, invalid(ErrIssuedAt, "DPoP proof iat outside acceptable window")
	}
	if r.AccessToken != "" {
		if c.ATH == "" || !equal(c.ATH, AccessTokenHash(r.AccessToken)) {
			return nil, invalid(ErrAccessToken, "DPoP proof ath mismatch")
		}
	}
	jkt, err := Thumbprint(pub)
	if err != nil {
		return nil, invalid(ErrKey, "DPoP proof jwk unacceptable")
	}
	if r.JKT != "" && !equal(jkt, r.JKT) {
		return nil, invalid(ErrThumbprint, "DPoP proof key does not match bound key")
	}
	if v.nonces != nil {
		if c.Nonce == "" || !v.nonces.Valid(ctx, c.Nonce) {
			return nil, &Error{Code: CodeUseNonce, Description: "Authorization server requires nonce in DPoP proof", Err: ErrNonce}
		}
	}
	if v.replay != nil {
		replayed, err := v.replay.Use(ctx, jkt, c.JTI, iat.Add(v.maxAge+v.leeway))
		if err != nil {
			return nil, invalid(fmt.Errorf("%w: %w", ErrReplayBackend, err), "DPoP proof could not be checked")
		}
		if replayed {
			return nil, invalid(ErrReplay, "DPoP proof replayed")
		}
	}
	return &Proof{
		Algorithm:       string(alg),
		PublicKey:       pub,
		JKT:             jkt,
		ID:              c.JTI,
		Method:          c.HTM,
		URI:             c.HTU,
		IssuedAt:        iat,
		Nonce:           c.Nonce,
		AccessTokenHash: c.ATH,
	}, nil
}

// checkHeader inspects the raw protected header before go-jose parses it:
// three segments, typ exactly dpop+jwt, alg allowed, no crit, jwk present
// and free of private or symmetric key members.
func (v *Verifier) checkHeader(proof string) error {
	parts := strings.Split(proof, ".")
	if len(parts) != 3 || parts[0] == "" {
		return invalid(ErrMalformed, "DPoP proof is not a signed JWT")
	}
	raw, err := base64.RawURLEncoding.DecodeString(parts[0])
	if err != nil {
		return invalid(ErrMalformed, "DPoP proof header malformed")
	}
	var h map[string]json.RawMessage
	if err := json.Unmarshal(raw, &h); err != nil {
		return invalid(ErrMalformed, "DPoP proof header malformed")
	}
	var typ string
	if t, ok := h["typ"]; !ok || json.Unmarshal(t, &typ) != nil || typ != ProofType {
		return invalid(ErrType, "DPoP proof typ must be dpop+jwt")
	}
	var alg string
	if a, ok := h["alg"]; !ok || json.Unmarshal(a, &alg) != nil || !v.allowed(alg) {
		return invalid(ErrAlgorithm, "DPoP proof algorithm not allowed")
	}
	if _, ok := h["crit"]; ok {
		return invalid(ErrMalformed, "DPoP proof must not use crit")
	}
	rawJWK, ok := h["jwk"]
	if !ok {
		return invalid(ErrKey, "DPoP proof jwk missing")
	}
	var jwk map[string]json.RawMessage
	if err := json.Unmarshal(rawJWK, &jwk); err != nil {
		return invalid(ErrKey, "DPoP proof jwk malformed")
	}
	var kty string
	if json.Unmarshal(jwk["kty"], &kty) != nil || (kty != "EC" && kty != "OKP") {
		return invalid(ErrKey, "DPoP proof jwk must be an EC or OKP public key")
	}
	for _, private := range []string{"d", "p", "q", "dp", "dq", "qi", "oth", "k"} {
		if _, ok := jwk[private]; ok {
			return invalid(ErrKey, "DPoP proof jwk must not contain private key material")
		}
	}
	if parts[1] == "" || parts[2] == "" {
		return invalid(ErrMalformed, "DPoP proof is not a signed JWT")
	}
	return nil
}

func (v *Verifier) allowed(alg string) bool {
	for _, a := range v.algs {
		if string(a) == alg {
			return true
		}
	}
	return false
}

func checkKey(alg string, jwk *jose.JSONWebKey) (crypto.PublicKey, error) {
	if !jwk.Valid() || !jwk.IsPublic() {
		return nil, invalid(ErrKey, "DPoP proof jwk must be a public key")
	}
	switch k := jwk.Key.(type) {
	case *ecdsa.PublicKey:
		if (alg == ES256 && k.Curve == elliptic.P256()) || (alg == ES384 && k.Curve == elliptic.P384()) {
			return k, nil
		}
	case ed25519.PublicKey:
		if alg == EdDSA && len(k) == ed25519.PublicKeySize {
			return k, nil
		}
	}
	return nil, invalid(ErrKey, "DPoP proof jwk does not match alg")
}

func numericDate(raw json.RawMessage) (time.Time, error) {
	// Only a JSON number is a NumericDate; json.Number alone would also
	// accept a quoted string.
	if len(raw) == 0 || !(raw[0] == '-' || ('0' <= raw[0] && raw[0] <= '9')) {
		return time.Time{}, errors.New("iat is not a number")
	}
	n := json.Number(raw)
	if i, err := n.Int64(); err == nil {
		if i <= 0 || i > 1<<40 {
			return time.Time{}, errors.New("out of range")
		}
		return time.Unix(i, 0), nil
	}
	f, err := n.Float64()
	if err != nil || math.IsNaN(f) || math.IsInf(f, 0) || f <= 0 || f > 1<<40 {
		return time.Time{}, errors.New("invalid NumericDate")
	}
	sec, frac := math.Modf(f)
	return time.Unix(int64(sec), int64(frac*1e9)), nil
}

func equal(a, b string) bool {
	return subtle.ConstantTimeCompare([]byte(a), []byte(b)) == 1
}
