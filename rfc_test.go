// Copyright 2026 Authfly
// SPDX-License-Identifier: Apache-2.0

package dpop_test

import (
	"context"
	"crypto/rsa"
	"encoding/base64"
	"errors"
	"math/big"
	"testing"
	"time"

	"github.com/authfly/dpop"
)

// Example proofs from RFC 9449 (Figures 2, 7 and 13). All use the same
// P-256 key whose thumbprint is given in RFC 9449 §6.1.
const (
	rfcJKT = "0ZcOCORZNYy-DWpqq30jZyJGHTN0d2HglBV3uiguA4I"

	rfcHeader = "eyJ0eXAiOiJkcG9wK2p3dCIsImFsZyI6IkVTMjU2IiwiandrIjp7Imt0eSI6Ik" +
		"VDIiwieCI6Imw4dEZyaHgtMzR0VjNoUklDUkRZOXpDa0RscEJoRjQyVVFVZldWQVdCR" +
		"nMiLCJ5IjoiOVZFNGpmX09rX282NHpiVFRsY3VOSmFqSG10NnY5VERWclUwQ2R2R1JE" +
		"QSIsImNydiI6IlAtMjU2In19"

	rfcFigure2 = rfcHeader + ".eyJqdGkiOiItQndDM0VTYzZhY2MybFRjIiwiaHRtIj" +
		"oiUE9TVCIsImh0dSI6Imh0dHBzOi8vc2VydmVyLmV4YW1wbGUuY29tL3Rva2VuIiwia" +
		"WF0IjoxNTYyMjYyNjE2fQ.2-GxA6T8lP4vfrg8v-FdWP0A0zdrj8igiMLvqRMUvwnQg" +
		"4PtFLbdLXiOSsX0x7NVY-FNyJK70nfbV37xRZT3Lg"

	rfcFigure7 = rfcHeader + ".eyJqdGkiOiItQndDM0VTYzZhY2MybFRjIiwiaHRtIj" +
		"oiUE9TVCIsImh0dSI6Imh0dHBzOi8vc2VydmVyLmV4YW1wbGUuY29tL3Rva2VuIiwia" +
		"WF0IjoxNTYyMjY1Mjk2fQ.pAqut2IRDm_De6PR93SYmGBPXpwrAk90e8cP2hjiaG5Qs" +
		"GSuKDYW7_X620BxqhvYC8ynrrvZLTk41mSRroapUA"

	rfcFigure13 = rfcHeader + ".eyJqdGkiOiJlMWozVl9iS2ljOC1MQUVCIiwiaHRtIj" +
		"oiR0VUIiwiaHR1IjoiaHR0cHM6Ly9yZXNvdXJjZS5leGFtcGxlLm9yZy9wcm90ZWN0Z" +
		"WRyZXNvdXJjZSIsImlhdCI6MTU2MjI2MjYxOCwiYXRoIjoiZlVIeU8ycjJaM0RaNTNF" +
		"c05yV0JiMHhXWG9hTnk1OUlpS0NBcWtzbVFFbyJ9.2oW9RP35yRqzhrtNP86L-Ey71E" +
		"OptxRimPPToA1plemAgR6pxHF8y6-yqyVnmcw6Fy1dqd-jfxSYoMxhAJpLjA"

	rfcAccessToken = "Kz~8mXK1EalYznwH-LC-1fBAo.4Ljp~zsPE_NeO.gxU"
)

func TestRFC9449Examples(t *testing.T) {
	tests := []struct {
		name  string
		proof string
		iat   int64
		req   dpop.Request
		jti   string
	}{
		{"figure2 token request", rfcFigure2, 1562262616,
			dpop.Request{Method: "POST", URL: "https://server.example.com/token"}, "-BwC3ESc6acc2lTc"},
		{"figure7 refresh", rfcFigure7, 1562265296,
			dpop.Request{Method: "POST", URL: "https://server.example.com/token", JKT: rfcJKT}, "-BwC3ESc6acc2lTc"},
		{"figure13 resource", rfcFigure13, 1562262618,
			dpop.Request{Method: "GET", URL: "https://resource.example.org/protectedresource",
				AccessToken: rfcAccessToken, JKT: rfcJKT}, "e1j3V_bKic8-LAEB"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			now := func() time.Time { return time.Unix(tt.iat+1, 0) }
			v, err := dpop.NewVerifier(dpop.Config{
				Replay: dpop.NewMemoryReplayCache(0).WithClock(now),
				Now:    now,
			})
			if err != nil {
				t.Fatal(err)
			}
			p, err := v.Verify(context.Background(), tt.proof, tt.req)
			if err != nil {
				t.Fatalf("Verify: %v", err)
			}
			if p.JKT != rfcJKT || p.ID != tt.jti || p.Algorithm != "ES256" || p.IssuedAt.Unix() != tt.iat {
				t.Fatalf("unexpected proof: %+v", p)
			}
			// Same proof again must be rejected as a replay.
			if _, err := v.Verify(context.Background(), tt.proof, tt.req); dpop.Code(err) != dpop.CodeInvalidProof {
				t.Fatalf("replay accepted: %v", err)
			}
		})
	}
}

func TestRFC9449Figure16(t *testing.T) {
	// A valid Figure 13 proof presented with a token bound to another key.
	now := func() time.Time { return time.Unix(1562262619, 0) }
	v, err := dpop.NewVerifier(dpop.Config{Replay: dpop.NewMemoryReplayCache(0).WithClock(now), Now: now})
	if err != nil {
		t.Fatal(err)
	}
	_, err = v.Verify(context.Background(), rfcFigure13, dpop.Request{Method: "GET",
		URL: "https://resource.example.org/protectedresource", AccessToken: rfcAccessToken,
		JKT: "NzbLsXh8uDCcd-6MNwXF4W_7noWXFZAfHkxZsRGC9Xs"})
	var e *dpop.Error
	if !errors.As(err, &e) || e.Code != dpop.CodeInvalidToken || !errors.Is(err, dpop.ErrThumbprint) {
		t.Fatalf("got %v", err)
	}
	want := `DPoP error="invalid_token", error_description="Invalid DPoP key binding", algs="ES256"`
	if got := dpop.WWWAuthenticate([]string{"ES256"}, e.Code, e.Description); got != want {
		t.Fatalf("got  %s\nwant %s", got, want)
	}
}

func TestRFC9449AccessTokenHash(t *testing.T) {
	// ath from Figure 14.
	if got, want := dpop.AccessTokenHash(rfcAccessToken), "fUHyO2r2Z3DZ53EsNrWBb0xWXoaNy59IiKCAqksmQEo"; got != want {
		t.Fatalf("ath = %s, want %s", got, want)
	}
}

func TestRFC7638Thumbprint(t *testing.T) {
	// RFC 7638 §3.1.
	n, err := base64.RawURLEncoding.DecodeString("0vx7agoebGcQSuuPiLJXZptN9nndrQmbXEps2aiAFbWhM78LhWx4" +
		"cbbfAAtVT86zwu1RK7aPFFxuhDR1L6tSoc_BJECPebWKRXjBZCiFV4n3oknjhMstn6" +
		"4tZ_2W-5JsGY4Hc5n9yBXArwl93lqt7_RN5w6Cf0h4QyQ5v-65YGjQR0_FDW2QvzqY" +
		"368QQMicAtaSqzs8KJZgnYb9c7d0zgdAZHzu6qMQvRL5hajrn1n91CbOpbISD08qNL" +
		"yrdkt-bFTWhAI4vMQFh6WeZu0fM4lFd2NcRwr3XPksINHaQ-G_xBniIqbw0Ls1jF44-" +
		"csFCur-kEgU8awapJzKnqDKgw")
	if err != nil {
		t.Fatal(err)
	}
	pub := &rsa.PublicKey{N: new(big.Int).SetBytes(n), E: 65537}
	got, err := dpop.Thumbprint(pub)
	if err != nil {
		t.Fatal(err)
	}
	if want := "NzbLsXh8uDCcd-6MNwXF4W_7noWXFZAfHkxZsRGC9Xs"; got != want {
		t.Fatalf("thumbprint = %s, want %s", got, want)
	}
}
