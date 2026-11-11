// Copyright 2026 Authfly
// SPDX-License-Identifier: Apache-2.0

package dpop_test

import (
	"context"
	"testing"
	"time"

	"github.com/authfly/dpop"
	"github.com/authfly/dpop/dpoptest"
)

func FuzzVerify(f *testing.F) {
	f.Add(rfcFigure2)
	f.Add(rfcFigure13)
	f.Add("")
	f.Add("a.b.c")
	f.Add("eyJ0eXAiOiJkcG9wK2p3dCJ9.e30.")
	k := dpoptest.MustKey(dpop.EdDSA)
	f.Add(k.Proof("POST", "https://server.example.com/token", dpoptest.Options{IssuedAt: time.Unix(1562262616, 0)}))
	now := func() time.Time { return time.Unix(1562262617, 0) }
	v, err := dpop.NewVerifier(dpop.Config{DisableReplayCheck: true, Now: now})
	if err != nil {
		f.Fatal(err)
	}
	req := dpop.Request{Method: "POST", URL: "https://server.example.com/token"}
	f.Fuzz(func(t *testing.T, proof string) {
		p, err := v.Verify(context.Background(), proof, req)
		if err == nil {
			if p == nil || p.JKT == "" || p.ID == "" || p.Method != "POST" {
				t.Fatalf("accepted incomplete proof: %+v", p)
			}
			return
		}
		if dpop.Code(err) == "" {
			t.Fatalf("untyped error: %v", err)
		}
	})
}

func FuzzNormalizeURI(f *testing.F) {
	for _, s := range []string{"https://a.example/x", "HTTP://A:80", "https://a/%7e%2f", "https://[::1]:443/"} {
		f.Add(s)
	}
	f.Fuzz(func(t *testing.T, s string) {
		n, err := dpop.NormalizeURI(s)
		if err != nil {
			return
		}
		// Normalization must be idempotent.
		n2, err := dpop.NormalizeURI(n)
		if err != nil || n2 != n {
			t.Fatalf("not idempotent: %q -> %q -> %q (%v)", s, n, n2, err)
		}
	})
}
