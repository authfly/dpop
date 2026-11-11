// Copyright 2026 Authfly
// SPDX-License-Identifier: Apache-2.0

package dpop_test

import (
	"context"
	"fmt"
	"net/http"

	"github.com/authfly/dpop"
	"github.com/authfly/dpop/dpoptest"
)

func ExampleVerifier_Verify() {
	verifier, err := dpop.NewVerifier(dpop.Config{Replay: dpop.NewMemoryReplayCache(0)})
	if err != nil {
		panic(err)
	}

	// A client request to the token endpoint.
	key := dpoptest.MustKey(dpop.ES256)
	h := http.Header{}
	h.Set("DPoP", key.Proof("POST", "https://as.example.com/oauth/token", dpoptest.Options{}))

	proof, err := dpop.ProofFromHeader(h)
	if err != nil {
		panic(err)
	}
	p, err := verifier.Verify(context.Background(), proof, dpop.Request{
		Method: "POST",
		URL:    "https://as.example.com/oauth/token",
	})
	if err != nil {
		fmt.Println(dpop.Code(err))
		return
	}
	fmt.Println(p.JKT == key.JKT())

	// The same proof is rejected the second time.
	_, err = verifier.Verify(context.Background(), proof, dpop.Request{Method: "POST", URL: "https://as.example.com/oauth/token"})
	fmt.Println(dpop.Code(err))
	// Output:
	// true
	// invalid_dpop_proof
}

func ExampleWWWAuthenticate() {
	fmt.Println(dpop.WWWAuthenticate([]string{"ES256", "EdDSA"}, dpop.CodeInvalidProof, "invalid DPoP proof"))
	// Output: DPoP error="invalid_dpop_proof", error_description="invalid DPoP proof", algs="ES256 EdDSA"
}
