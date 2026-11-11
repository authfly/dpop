// Copyright 2026 Authfly
// SPDX-License-Identifier: Apache-2.0

// Package dpoptest creates DPoP proofs for tests. It is not a production
// client: keys live in memory and there is no protection against misuse.
package dpoptest

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"crypto/sha512"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"time"

	jose "github.com/go-jose/go-jose/v4"

	"github.com/authfly/dpop"
)

// Key is a proof signing key.
type Key struct {
	Alg     string
	Private crypto.Signer
}

// NewKey generates a key for alg (ES256, ES384 or EdDSA).
func NewKey(alg string) (*Key, error) {
	var (
		k   crypto.Signer
		err error
	)
	switch alg {
	case dpop.ES256:
		k, err = ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	case dpop.ES384:
		k, err = ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	case dpop.EdDSA:
		_, k, err = ed25519.GenerateKey(rand.Reader)
	default:
		return nil, fmt.Errorf("dpoptest: unsupported alg %q", alg)
	}
	if err != nil {
		return nil, err
	}
	return &Key{Alg: alg, Private: k}, nil
}

// MustKey is NewKey that panics on error.
func MustKey(alg string) *Key {
	k, err := NewKey(alg)
	if err != nil {
		panic(err)
	}
	return k
}

// PublicJWK returns the public key as a JWK object.
func (k *Key) PublicJWK() map[string]any { return jwkMap(k.Private.Public()) }

// PrivateJWK returns the key including private members (for negative tests).
func (k *Key) PrivateJWK() map[string]any { return jwkMap(k.Private) }

// JKT returns the RFC 7638 thumbprint of the public key.
func (k *Key) JKT() string {
	t, err := dpop.Thumbprint(k.Private.Public())
	if err != nil {
		panic(err)
	}
	return t
}

// Options customize a proof. Zero values pick sensible defaults.
type Options struct {
	JTI         string    // default: random
	IssuedAt    time.Time // default: time.Now()
	Nonce       string
	AccessToken string // sets ath
	// Header and Claims override or add members; a nil value removes one.
	Header map[string]any
	Claims map[string]any
}

// Proof returns a signed proof for method and uri.
func (k *Key) Proof(method, uri string, o Options) string {
	if o.JTI == "" {
		b := make([]byte, 16)
		_, _ = rand.Read(b)
		o.JTI = base64.RawURLEncoding.EncodeToString(b)
	}
	if o.IssuedAt.IsZero() {
		o.IssuedAt = time.Now()
	}
	h := map[string]any{"typ": dpop.ProofType, "alg": k.Alg, "jwk": k.PublicJWK()}
	c := map[string]any{"jti": o.JTI, "htm": method, "htu": uri, "iat": o.IssuedAt.Unix()}
	if o.Nonce != "" {
		c["nonce"] = o.Nonce
	}
	if o.AccessToken != "" {
		c["ath"] = dpop.AccessTokenHash(o.AccessToken)
	}
	merge(h, o.Header)
	merge(c, o.Claims)
	return k.Sign(h, c)
}

// Sign serializes header and claims and signs them with the key's own
// algorithm, regardless of the alg value in header.
func (k *Key) Sign(header, claims map[string]any) string {
	input := encode(header) + "." + encode(claims)
	var sig []byte
	switch p := k.Private.(type) {
	case *ecdsa.PrivateKey:
		var digest []byte
		if p.Curve == elliptic.P384() {
			s := sha512.Sum384([]byte(input))
			digest = s[:]
		} else {
			s := sha256.Sum256([]byte(input))
			digest = s[:]
		}
		r, s, err := ecdsa.Sign(rand.Reader, p, digest)
		if err != nil {
			panic(err)
		}
		size := (p.Curve.Params().BitSize + 7) / 8
		sig = make([]byte, 2*size)
		r.FillBytes(sig[:size])
		s.FillBytes(sig[size:])
	case ed25519.PrivateKey:
		sig = ed25519.Sign(p, []byte(input))
	}
	return input + "." + base64.RawURLEncoding.EncodeToString(sig)
}

// SignHS256 returns an HMAC-signed token (always invalid for DPoP).
func SignHS256(secret []byte, header, claims map[string]any) string {
	input := encode(header) + "." + encode(claims)
	m := hmac.New(sha256.New, secret)
	m.Write([]byte(input))
	return input + "." + base64.RawURLEncoding.EncodeToString(m.Sum(nil))
}

// Unsigned returns an alg=none style token with an empty signature segment.
func Unsigned(header, claims map[string]any) string {
	return encode(header) + "." + encode(claims) + "."
}

func encode(v any) string {
	b, err := json.Marshal(v)
	if err != nil {
		panic(err)
	}
	return base64.RawURLEncoding.EncodeToString(b)
}

func merge(dst, src map[string]any) {
	for k, v := range src {
		if v == nil {
			delete(dst, k)
		} else {
			dst[k] = v
		}
	}
}

func jwkMap(key any) map[string]any {
	b, err := json.Marshal(jose.JSONWebKey{Key: key})
	if err != nil {
		panic(err)
	}
	var m map[string]any
	if err := json.Unmarshal(b, &m); err != nil {
		panic(err)
	}
	return m
}
