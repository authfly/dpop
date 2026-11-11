// Copyright 2026 Authfly
// SPDX-License-Identifier: Apache-2.0

// Package dpop verifies OAuth 2.0 Demonstrating Proof of Possession (DPoP)
// proofs as defined in RFC 9449.
//
// It is meant for the server side: an authorization server token endpoint
// that issues DPoP-bound tokens, and resource servers that accept them.
// The package does not issue tokens and does not talk to any token store;
// it validates a single proof JWT against the HTTP request it arrived with
// and returns the JWK SHA-256 thumbprint (jkt, RFC 7638) of the proof key.
//
// Status: experimental, not audited. The API may change before v1.
package dpop
