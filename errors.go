// Copyright 2026 Authfly
// SPDX-License-Identifier: Apache-2.0

package dpop

import (
	"errors"
	"strings"
)

// OAuth error codes defined by RFC 9449.
const (
	// CodeInvalidProof is returned when the DPoP proof is missing, malformed
	// or fails any check (RFC 9449 §5, §7.1).
	CodeInvalidProof = "invalid_dpop_proof"
	// CodeUseNonce is returned when the server requires a nonce and the proof
	// has none or a stale one (RFC 9449 §8, §9).
	CodeUseNonce = "use_dpop_nonce"
)

// Reasons wrapped by *Error. Use errors.Is to test for them. They are meant
// for logging and metrics; do not echo internal details to clients beyond the
// error code.
var (
	ErrMissing       = errors.New("dpop: missing proof")
	ErrMultiple      = errors.New("dpop: more than one DPoP header")
	ErrMalformed     = errors.New("dpop: malformed proof")
	ErrType          = errors.New("dpop: typ header is not dpop+jwt")
	ErrAlgorithm     = errors.New("dpop: algorithm not allowed")
	ErrKey           = errors.New("dpop: unacceptable jwk")
	ErrSignature     = errors.New("dpop: invalid signature")
	ErrMethod        = errors.New("dpop: htm does not match request method")
	ErrURI           = errors.New("dpop: htu does not match request URI")
	ErrIssuedAt      = errors.New("dpop: iat outside acceptable window")
	ErrReplay        = errors.New("dpop: proof replayed")
	ErrAccessToken   = errors.New("dpop: ath does not match access token")
	ErrThumbprint    = errors.New("dpop: key thumbprint does not match")
	ErrNonce         = errors.New("dpop: nonce missing or invalid")
	ErrReplayBackend = errors.New("dpop: replay cache failure")
)

// Error is the error type returned by Verifier.Verify. Code is one of
// CodeInvalidProof or CodeUseNonce and is safe to send to clients.
type Error struct {
	Code        string
	Description string
	Err         error
}

func (e *Error) Error() string {
	if e.Err != nil {
		return e.Code + ": " + e.Err.Error()
	}
	return e.Code + ": " + e.Description
}

func (e *Error) Unwrap() error { return e.Err }

func invalid(reason error, desc string) *Error {
	return &Error{Code: CodeInvalidProof, Description: desc, Err: reason}
}

// Code returns the RFC 9449 error code for err, or "" if err is not a *Error.
func Code(err error) string {
	var e *Error
	if errors.As(err, &e) {
		return e.Code
	}
	return ""
}

// WWWAuthenticate builds the value of a WWW-Authenticate response header with
// the DPoP scheme for resource servers (RFC 9449 §7.1). algs lists the
// accepted JWS algorithms (may be empty). code and description may be empty
// for a plain challenge; code may be invalid_dpop_proof, use_dpop_nonce or an
// RFC 6750 code such as invalid_token.
//
// Characters not allowed by RFC 6750 §3 in error_description are dropped.
func WWWAuthenticate(algs []string, code, description string) string {
	var b strings.Builder
	b.WriteString("DPoP")
	sep := " "
	add := func(k, v string) {
		b.WriteString(sep)
		b.WriteString(k)
		b.WriteString(`="`)
		b.WriteString(v)
		b.WriteString(`"`)
		sep = ", "
	}
	if code != "" {
		add("error", sanitize(code))
	}
	if description != "" {
		add("error_description", sanitize(description))
	}
	if len(algs) > 0 {
		clean := make([]string, 0, len(algs))
		for _, a := range algs {
			if s := sanitize(a); s != "" {
				clean = append(clean, strings.ReplaceAll(s, " ", ""))
			}
		}
		add("algs", strings.Join(clean, " "))
	}
	return b.String()
}

// sanitize keeps only %x20-21 / %x23-5B / %x5D-7E (RFC 6750 §3).
func sanitize(s string) string {
	return strings.Map(func(r rune) rune {
		if r == 0x20 || r == 0x21 || (r >= 0x23 && r <= 0x5B) || (r >= 0x5D && r <= 0x7E) {
			return r
		}
		return -1
	}, s)
}
