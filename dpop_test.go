// Copyright 2026 Authfly
// SPDX-License-Identifier: Apache-2.0

package dpop_test

import (
	"context"
	"errors"
	"net/http"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/authfly/dpop"
	"github.com/authfly/dpop/dpoptest"
)

const (
	tokenURL = "https://as.example.com/oauth/token"
	apiURL   = "https://api.example.com/v1/me"
)

var fixedNow = time.Unix(1_800_000_000, 0)

func newVerifier(t *testing.T, mod func(*dpop.Config)) *dpop.Verifier {
	t.Helper()
	now := func() time.Time { return fixedNow }
	cfg := dpop.Config{Replay: dpop.NewMemoryReplayCache(0).WithClock(now), Now: now}
	if mod != nil {
		mod(&cfg)
	}
	v, err := dpop.NewVerifier(cfg)
	if err != nil {
		t.Fatal(err)
	}
	return v
}

func TestVerifyValid(t *testing.T) {
	for _, alg := range []string{dpop.ES256, dpop.ES384, dpop.EdDSA} {
		t.Run(alg, func(t *testing.T) {
			v := newVerifier(t, func(c *dpop.Config) { c.Algorithms = []string{dpop.ES256, dpop.ES384, dpop.EdDSA} })
			k := dpoptest.MustKey(alg)
			proof := k.Proof("POST", tokenURL, dpoptest.Options{IssuedAt: fixedNow})
			p, err := v.Verify(context.Background(), proof, dpop.Request{Method: "POST", URL: tokenURL, JKT: k.JKT()})
			if err != nil {
				t.Fatal(err)
			}
			if p.JKT != k.JKT() || p.Algorithm != alg || p.Method != "POST" || p.URI != tokenURL {
				t.Fatalf("unexpected proof %+v", p)
			}
		})
	}
}

func TestDefaultAlgorithmsRejectES384(t *testing.T) {
	v := newVerifier(t, nil)
	k := dpoptest.MustKey(dpop.ES384)
	_, err := v.Verify(context.Background(), k.Proof("POST", tokenURL, dpoptest.Options{IssuedAt: fixedNow}),
		dpop.Request{Method: "POST", URL: tokenURL})
	if !errors.Is(err, dpop.ErrAlgorithm) {
		t.Fatalf("got %v, want ErrAlgorithm", err)
	}
}

func TestVerifyResourceServer(t *testing.T) {
	v := newVerifier(t, nil)
	k := dpoptest.MustKey(dpop.ES256)
	proof := k.Proof("GET", apiURL+"?x=1#frag", dpoptest.Options{IssuedAt: fixedNow, AccessToken: "at-123"})
	p, err := v.Verify(context.Background(), proof, dpop.Request{
		Method: "GET", URL: "HTTPS://API.example.com:443/v1/me?other=2", AccessToken: "at-123", JKT: k.JKT(),
	})
	if err != nil {
		t.Fatal(err)
	}
	if p.AccessTokenHash != dpop.AccessTokenHash("at-123") {
		t.Fatalf("ath = %q", p.AccessTokenHash)
	}
}

func TestVerifyRejects(t *testing.T) {
	k := dpoptest.MustKey(dpop.ES256)
	other := dpoptest.MustKey(dpop.ES256)
	ed := dpoptest.MustKey(dpop.EdDSA)
	base := dpop.Request{Method: "POST", URL: tokenURL}
	opts := func(o dpoptest.Options) dpoptest.Options {
		if o.IssuedAt.IsZero() {
			o.IssuedAt = fixedNow
		}
		return o
	}
	goodClaims := map[string]any{"jti": "j1", "htm": "POST", "htu": tokenURL, "iat": fixedNow.Unix()}

	tests := []struct {
		name  string
		proof string
		req   dpop.Request
		want  error
	}{
		{"empty", "", base, dpop.ErrMissing},
		{"not a jwt", "abc", base, dpop.ErrMalformed},
		{"two segments", "a.b", base, dpop.ErrMalformed},
		{"garbage header", "!!!.e30.sig", base, dpop.ErrMalformed},
		{"too large", strings.Repeat("a", dpop.DefaultMaxProofSize+1), base, dpop.ErrMalformed},
		{"typ missing", k.Proof("POST", tokenURL, opts(dpoptest.Options{Header: map[string]any{"typ": nil}})), base, dpop.ErrType},
		{"typ jwt", k.Proof("POST", tokenURL, opts(dpoptest.Options{Header: map[string]any{"typ": "JWT"}})), base, dpop.ErrType},
		{"typ case", k.Proof("POST", tokenURL, opts(dpoptest.Options{Header: map[string]any{"typ": "DPoP+JWT"}})), base, dpop.ErrType},
		{"alg none", dpoptest.Unsigned(map[string]any{"typ": "dpop+jwt", "alg": "none", "jwk": k.PublicJWK()}, goodClaims), base, dpop.ErrAlgorithm},
		{"alg HS256", dpoptest.SignHS256([]byte("secret"), map[string]any{"typ": "dpop+jwt", "alg": "HS256", "jwk": map[string]any{"kty": "oct", "k": "c2VjcmV0"}}, goodClaims), base, dpop.ErrAlgorithm},
		{"alg RS256", k.Proof("POST", tokenURL, opts(dpoptest.Options{Header: map[string]any{"alg": "RS256"}})), base, dpop.ErrAlgorithm},
		{"alg missing", k.Proof("POST", tokenURL, opts(dpoptest.Options{Header: map[string]any{"alg": nil}})), base, dpop.ErrAlgorithm},
		{"symmetric jwk", k.Proof("POST", tokenURL, opts(dpoptest.Options{Header: map[string]any{"jwk": map[string]any{"kty": "oct", "k": "c2VjcmV0"}}})), base, dpop.ErrKey},
		{"private jwk", k.Proof("POST", tokenURL, opts(dpoptest.Options{Header: map[string]any{"jwk": k.PrivateJWK()}})), base, dpop.ErrKey},
		{"private ed jwk", ed.Proof("POST", tokenURL, opts(dpoptest.Options{Header: map[string]any{"jwk": ed.PrivateJWK()}})), base, dpop.ErrKey},
		{"jwk missing", k.Proof("POST", tokenURL, opts(dpoptest.Options{Header: map[string]any{"jwk": nil}})), base, dpop.ErrKey},
		{"jwk not object", k.Proof("POST", tokenURL, opts(dpoptest.Options{Header: map[string]any{"jwk": "x"}})), base, dpop.ErrKey},
		{"jwk alg mismatch", k.Proof("POST", tokenURL, opts(dpoptest.Options{Header: map[string]any{"jwk": ed.PublicJWK()}})), base, dpop.ErrKey},
		{"crit header", k.Proof("POST", tokenURL, opts(dpoptest.Options{Header: map[string]any{"crit": []string{"b64"}, "b64": false}})), base, dpop.ErrMalformed},
		{"wrong key signature", k.Proof("POST", tokenURL, opts(dpoptest.Options{Header: map[string]any{"jwk": other.PublicJWK()}})), base, dpop.ErrSignature},
		{"tampered payload", tamper(k.Proof("POST", tokenURL, opts(dpoptest.Options{}))), base, dpop.ErrSignature},
		{"jti missing", k.Proof("POST", tokenURL, opts(dpoptest.Options{Claims: map[string]any{"jti": nil}})), base, dpop.ErrMalformed},
		{"jti too long", k.Proof("POST", tokenURL, opts(dpoptest.Options{JTI: strings.Repeat("j", 257)})), base, dpop.ErrMalformed},
		{"jti number", k.Proof("POST", tokenURL, opts(dpoptest.Options{Claims: map[string]any{"jti": 5}})), base, dpop.ErrMalformed},
		{"htm missing", k.Proof("POST", tokenURL, opts(dpoptest.Options{Claims: map[string]any{"htm": nil}})), base, dpop.ErrMalformed},
		{"htu missing", k.Proof("POST", tokenURL, opts(dpoptest.Options{Claims: map[string]any{"htu": nil}})), base, dpop.ErrMalformed},
		{"iat missing", k.Proof("POST", tokenURL, opts(dpoptest.Options{Claims: map[string]any{"iat": nil}})), base, dpop.ErrMalformed},
		{"iat string", k.Proof("POST", tokenURL, opts(dpoptest.Options{Claims: map[string]any{"iat": "1800000000"}})), base, dpop.ErrMalformed},
		{"iat negative", k.Proof("POST", tokenURL, opts(dpoptest.Options{Claims: map[string]any{"iat": -1}})), base, dpop.ErrMalformed},
		{"htm mismatch", k.Proof("GET", tokenURL, opts(dpoptest.Options{})), base, dpop.ErrMethod},
		{"htm case", k.Proof("post", tokenURL, opts(dpoptest.Options{})), base, dpop.ErrMethod},
		{"htu other path", k.Proof("POST", "https://as.example.com/oauth/token2", opts(dpoptest.Options{})), base, dpop.ErrURI},
		{"htu other host", k.Proof("POST", "https://evil.example.com/oauth/token", opts(dpoptest.Options{})), base, dpop.ErrURI},
		{"htu http", k.Proof("POST", "http://as.example.com/oauth/token", opts(dpoptest.Options{})), base, dpop.ErrURI},
		{"htu other port", k.Proof("POST", "https://as.example.com:8443/oauth/token", opts(dpoptest.Options{})), base, dpop.ErrURI},
		{"htu relative", k.Proof("POST", "/oauth/token", opts(dpoptest.Options{})), base, dpop.ErrURI},
		{"iat stale", k.Proof("POST", tokenURL, dpoptest.Options{IssuedAt: fixedNow.Add(-dpop.DefaultMaxAge - time.Second)}), base, dpop.ErrIssuedAt},
		{"iat future", k.Proof("POST", tokenURL, dpoptest.Options{IssuedAt: fixedNow.Add(dpop.DefaultLeeway + time.Second)}), base, dpop.ErrIssuedAt},
		{"ath missing", k.Proof("POST", tokenURL, opts(dpoptest.Options{})), dpop.Request{Method: "POST", URL: tokenURL, AccessToken: "at"}, dpop.ErrAccessToken},
		{"ath wrong", k.Proof("POST", tokenURL, opts(dpoptest.Options{AccessToken: "other"})), dpop.Request{Method: "POST", URL: tokenURL, AccessToken: "at"}, dpop.ErrAccessToken},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			v := newVerifier(t, nil)
			p, err := v.Verify(context.Background(), tt.proof, tt.req)
			if err == nil {
				t.Fatalf("accepted: %+v", p)
			}
			if !errors.Is(err, tt.want) {
				t.Fatalf("got %v, want %v", err, tt.want)
			}
			if dpop.Code(err) != dpop.CodeInvalidProof {
				t.Fatalf("code = %q", dpop.Code(err))
			}
		})
	}
}

func tamper(proof string) string {
	parts := strings.Split(proof, ".")
	parts[1] = "eyJqdGkiOiJ4IiwiaHRtIjoiUE9TVCIsImh0dSI6Imh0dHBzOi8vYXMuZXhhbXBsZS5jb20vb2F1dGgvdG9rZW4iLCJpYXQiOjE4MDAwMDAwMDB9"
	return strings.Join(parts, ".")
}

func TestReplay(t *testing.T) {
	v := newVerifier(t, nil)
	k := dpoptest.MustKey(dpop.ES256)
	proof := k.Proof("POST", tokenURL, dpoptest.Options{IssuedAt: fixedNow})
	req := dpop.Request{Method: "POST", URL: tokenURL}
	if _, err := v.Verify(context.Background(), proof, req); err != nil {
		t.Fatal(err)
	}
	if _, err := v.Verify(context.Background(), proof, req); !errors.Is(err, dpop.ErrReplay) {
		t.Fatalf("got %v, want ErrReplay", err)
	}
	// Same jti under a different key is a different proof.
	k2 := dpoptest.MustKey(dpop.ES256)
	if _, err := v.Verify(context.Background(), k2.Proof("POST", tokenURL, dpoptest.Options{IssuedAt: fixedNow, JTI: "shared"}), req); err != nil {
		t.Fatal(err)
	}
	if _, err := v.Verify(context.Background(), k.Proof("POST", tokenURL, dpoptest.Options{IssuedAt: fixedNow, JTI: "shared"}), req); err != nil {
		t.Fatal(err)
	}
}

func TestReplayConcurrent(t *testing.T) {
	v := newVerifier(t, nil)
	k := dpoptest.MustKey(dpop.EdDSA)
	proof := k.Proof("POST", tokenURL, dpoptest.Options{IssuedAt: fixedNow})
	var ok atomic.Int32
	var wg sync.WaitGroup
	for i := 0; i < 64; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if _, err := v.Verify(context.Background(), proof, dpop.Request{Method: "POST", URL: tokenURL}); err == nil {
				ok.Add(1)
			}
		}()
	}
	wg.Wait()
	if ok.Load() != 1 {
		t.Fatalf("%d concurrent verifications succeeded, want 1", ok.Load())
	}
}

type failingCache struct{}

func (failingCache) Use(context.Context, string, string, time.Time) (bool, error) {
	return false, errors.New("backend down")
}

func TestReplayBackendFailsClosed(t *testing.T) {
	v := newVerifier(t, func(c *dpop.Config) { c.Replay = failingCache{} })
	k := dpoptest.MustKey(dpop.ES256)
	_, err := v.Verify(context.Background(), k.Proof("POST", tokenURL, dpoptest.Options{IssuedAt: fixedNow}), dpop.Request{Method: "POST", URL: tokenURL})
	if !errors.Is(err, dpop.ErrReplayBackend) {
		t.Fatalf("got %v", err)
	}
}

type staticNonces struct{ valid string }

func (s staticNonces) Nonce(context.Context) (string, error)  { return s.valid, nil }
func (s staticNonces) Valid(_ context.Context, n string) bool { return n == s.valid }

func TestNonce(t *testing.T) {
	v := newVerifier(t, func(c *dpop.Config) { c.Nonces = staticNonces{"n-1"} })
	k := dpoptest.MustKey(dpop.ES256)
	req := dpop.Request{Method: "POST", URL: tokenURL}
	for _, n := range []string{"", "n-0"} {
		_, err := v.Verify(context.Background(), k.Proof("POST", tokenURL, dpoptest.Options{IssuedAt: fixedNow, Nonce: n}), req)
		if dpop.Code(err) != dpop.CodeUseNonce || !errors.Is(err, dpop.ErrNonce) {
			t.Fatalf("nonce %q: got %v", n, err)
		}
	}
	p, err := v.Verify(context.Background(), k.Proof("POST", tokenURL, dpoptest.Options{IssuedAt: fixedNow, Nonce: "n-1"}), req)
	if err != nil || p.Nonce != "n-1" {
		t.Fatalf("got %v %+v", err, p)
	}
	h := http.Header{}
	if !dpop.SetNonce(h, "n-1") || h.Get("DPoP-Nonce") != "n-1" {
		t.Fatal("SetNonce failed")
	}
	if dpop.SetNonce(h, `bad"nonce`) || dpop.SetNonce(h, "") || dpop.SetNonce(h, "a b") {
		t.Fatal("SetNonce accepted invalid value")
	}
}

func TestNewVerifierConfig(t *testing.T) {
	if _, err := dpop.NewVerifier(dpop.Config{}); err == nil {
		t.Fatal("missing Replay accepted")
	}
	if _, err := dpop.NewVerifier(dpop.Config{DisableReplayCheck: true}); err != nil {
		t.Fatal(err)
	}
	for _, alg := range []string{"HS256", "none", "RS256", "es256"} {
		if _, err := dpop.NewVerifier(dpop.Config{DisableReplayCheck: true, Algorithms: []string{alg}}); err == nil {
			t.Fatalf("alg %q accepted", alg)
		}
	}
	if _, err := dpop.NewVerifier(dpop.Config{DisableReplayCheck: true, MaxAge: -time.Second}); err == nil {
		t.Fatal("negative MaxAge accepted")
	}
	v, _ := dpop.NewVerifier(dpop.Config{DisableReplayCheck: true})
	if got := strings.Join(v.Algorithms(), " "); got != "ES256 EdDSA" {
		t.Fatalf("Algorithms = %q", got)
	}
}

func TestBadRequestURL(t *testing.T) {
	v := newVerifier(t, nil)
	k := dpoptest.MustKey(dpop.ES256)
	_, err := v.Verify(context.Background(), k.Proof("POST", tokenURL, dpoptest.Options{IssuedAt: fixedNow}), dpop.Request{Method: "POST", URL: "/relative"})
	if err == nil || dpop.Code(err) != "" {
		t.Fatalf("got %v, want configuration error", err)
	}
}

func TestProofFromHeader(t *testing.T) {
	h := http.Header{}
	if _, err := dpop.ProofFromHeader(h); !errors.Is(err, dpop.ErrMissing) {
		t.Fatalf("got %v", err)
	}
	h.Set("dpop", " a.b.c ")
	if got, err := dpop.ProofFromHeader(h); err != nil || got != "a.b.c" {
		t.Fatalf("got %q %v", got, err)
	}
	h.Add("DPoP", "d.e.f")
	if _, err := dpop.ProofFromHeader(h); !errors.Is(err, dpop.ErrMultiple) {
		t.Fatalf("got %v", err)
	}
	h = http.Header{"Dpop": {"a.b.c, d.e.f"}}
	if _, err := dpop.ProofFromHeader(h); !errors.Is(err, dpop.ErrMultiple) {
		t.Fatalf("got %v", err)
	}
}

func TestWWWAuthenticate(t *testing.T) {
	tests := []struct {
		algs       []string
		code, desc string
		want       string
	}{
		{nil, "", "", "DPoP"},
		{[]string{"ES256", "EdDSA"}, "", "", `DPoP algs="ES256 EdDSA"`},
		{[]string{"ES256"}, dpop.CodeUseNonce, "Resource server requires nonce in DPoP proof",
			`DPoP error="use_dpop_nonce", error_description="Resource server requires nonce in DPoP proof", algs="ES256"`},
		{nil, dpop.CodeInvalidProof, "bad \"quote\" \\ and\nnewline",
			`DPoP error="invalid_dpop_proof", error_description="bad quote  andnewline"`},
	}
	for _, tt := range tests {
		if got := dpop.WWWAuthenticate(tt.algs, tt.code, tt.desc); got != tt.want {
			t.Errorf("got  %s\nwant %s", got, tt.want)
		}
	}
}

func TestErrorFormatting(t *testing.T) {
	v := newVerifier(t, nil)
	_, err := v.Verify(context.Background(), "x", dpop.Request{Method: "POST", URL: tokenURL})
	var e *dpop.Error
	if !errors.As(err, &e) || e.Code != dpop.CodeInvalidProof || e.Description == "" || !strings.HasPrefix(err.Error(), "invalid_dpop_proof: ") {
		t.Fatalf("got %#v", err)
	}
	if dpop.Code(errors.New("x")) != "" {
		t.Fatal("Code of foreign error")
	}
	if (&dpop.Error{Code: "c", Description: "d"}).Error() != "c: d" {
		t.Fatal("Error() without cause")
	}
}

func TestKeyBindingMismatch(t *testing.T) {
	k := dpoptest.MustKey(dpop.ES256)
	other := dpoptest.MustKey(dpop.ES256)
	tests := []struct {
		name     string
		proof    string
		req      dpop.Request
		wantCode string
		wantErr  error
	}{
		{"token endpoint", k.Proof("POST", tokenURL, dpoptest.Options{IssuedAt: fixedNow}),
			dpop.Request{Method: "POST", URL: tokenURL, JKT: other.JKT()}, dpop.CodeInvalidGrant, dpop.ErrThumbprint},
		{"resource server", k.Proof("GET", apiURL, dpoptest.Options{IssuedAt: fixedNow, AccessToken: "at"}),
			dpop.Request{Method: "GET", URL: apiURL, AccessToken: "at", JKT: other.JKT()}, dpop.CodeInvalidToken, dpop.ErrThumbprint},
		// Proof failures checked before the binding stay invalid_dpop_proof.
		{"token endpoint bad htu", k.Proof("POST", tokenURL+"x", dpoptest.Options{IssuedAt: fixedNow}),
			dpop.Request{Method: "POST", URL: tokenURL, JKT: other.JKT()}, dpop.CodeInvalidProof, dpop.ErrURI},
		{"resource server bad ath", k.Proof("GET", apiURL, dpoptest.Options{IssuedAt: fixedNow, AccessToken: "other"}),
			dpop.Request{Method: "GET", URL: apiURL, AccessToken: "at", JKT: other.JKT()}, dpop.CodeInvalidProof, dpop.ErrAccessToken},
		{"resource server stale", k.Proof("GET", apiURL, dpoptest.Options{IssuedAt: fixedNow.Add(-time.Hour), AccessToken: "at"}),
			dpop.Request{Method: "GET", URL: apiURL, AccessToken: "at", JKT: other.JKT()}, dpop.CodeInvalidProof, dpop.ErrIssuedAt},
		{"resource server bad signature", tamper(k.Proof("GET", apiURL, dpoptest.Options{IssuedAt: fixedNow})),
			dpop.Request{Method: "GET", URL: apiURL, AccessToken: "at", JKT: other.JKT()}, dpop.CodeInvalidProof, dpop.ErrSignature},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			v := newVerifier(t, nil)
			_, err := v.Verify(context.Background(), tt.proof, tt.req)
			if !errors.Is(err, tt.wantErr) || dpop.Code(err) != tt.wantCode {
				t.Fatalf("got %v (code %q), want %v (code %q)", err, dpop.Code(err), tt.wantErr, tt.wantCode)
			}
		})
	}
}

func TestKeyBindingMismatchDoesNotConsumeProof(t *testing.T) {
	v := newVerifier(t, nil)
	k := dpoptest.MustKey(dpop.ES256)
	other := dpoptest.MustKey(dpop.ES256)
	proof := k.Proof("POST", tokenURL, dpoptest.Options{IssuedAt: fixedNow})
	if _, err := v.Verify(context.Background(), proof, dpop.Request{Method: "POST", URL: tokenURL, JKT: other.JKT()}); dpop.Code(err) != dpop.CodeInvalidGrant {
		t.Fatalf("got %v", err)
	}
	if _, err := v.Verify(context.Background(), proof, dpop.Request{Method: "POST", URL: tokenURL, JKT: k.JKT()}); err != nil {
		t.Fatalf("matching key rejected after mismatch: %v", err)
	}
}
