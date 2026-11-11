// Copyright 2026 Authfly
// SPDX-License-Identifier: Apache-2.0

package dpop_test

import (
	"testing"

	"github.com/authfly/dpop"
)

func TestNormalizeURI(t *testing.T) {
	tests := []struct{ in, want string }{
		{"https://server.example.com/token", "https://server.example.com/token"},
		{"HTTPS://Server.Example.COM/token", "https://server.example.com/token"},
		{"https://server.example.com:443/token", "https://server.example.com/token"},
		{"http://server.example.com:80/token", "http://server.example.com/token"},
		{"http://server.example.com:443/token", "http://server.example.com:443/token"},
		{"https://server.example.com:/token", "https://server.example.com/token"},
		{"https://server.example.com", "https://server.example.com/"},
		{"https://server.example.com/token?a=b#frag", "https://server.example.com/token"},
		{"https://server.example.com/%7Euser/a%2fb", "https://server.example.com/~user/a%2Fb"},
		{"https://server.example.com/Token", "https://server.example.com/Token"},
		{"https://[::1]:8443/x", "https://[::1]:8443/x"},
	}
	for _, tt := range tests {
		got, err := dpop.NormalizeURI(tt.in)
		if err != nil || got != tt.want {
			t.Errorf("NormalizeURI(%q) = %q, %v; want %q", tt.in, got, err, tt.want)
		}
	}
	for _, bad := range []string{"", "/token", "ftp://x/y", "mailto:a@b", "https:opaque", "https://", "%zz", "https://x/%zz"} {
		if got, err := dpop.NormalizeURI(bad); err == nil {
			t.Errorf("NormalizeURI(%q) = %q, want error", bad, got)
		}
	}
}
