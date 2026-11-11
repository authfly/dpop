// Copyright 2026 Authfly
// SPDX-License-Identifier: Apache-2.0

package dpop

import (
	"context"
	"net/http"
)

// NonceHeader is the response header carrying a server-provided nonce
// (RFC 9449 §8.1).
const NonceHeader = "DPoP-Nonce"

// NonceSource lets a server require server-provided nonces (RFC 9449 §8, §9).
// Implementations decide how nonces are generated and how long they stay
// valid (for example a rotating HMAC over a time slot). Both methods must be
// safe for concurrent use.
type NonceSource interface {
	// Nonce returns the nonce the client should use next. Servers send it
	// in the DPoP-Nonce header, both with use_dpop_nonce errors and,
	// optionally, on successful responses.
	Nonce(ctx context.Context) (string, error)
	// Valid reports whether nonce is currently acceptable.
	Valid(ctx context.Context, nonce string) bool
}

// SetNonce sets the DPoP-Nonce header. The value must match the NQCHAR
// syntax (%x21 / %x23-5B / %x5D-7E); invalid values are not set and false is
// returned.
func SetNonce(h http.Header, nonce string) bool {
	if !validNonce(nonce) {
		return false
	}
	h.Set(NonceHeader, nonce)
	return true
}

func validNonce(s string) bool {
	if s == "" {
		return false
	}
	for i := 0; i < len(s); i++ {
		c := s[i]
		if !(c == 0x21 || (c >= 0x23 && c <= 0x5B) || (c >= 0x5D && c <= 0x7E)) {
			return false
		}
	}
	return true
}
