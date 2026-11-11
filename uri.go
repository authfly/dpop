// Copyright 2026 Authfly
// SPDX-License-Identifier: Apache-2.0

package dpop

import (
	"errors"
	"net/url"
	"strings"
)

// NormalizeURI returns the form of an HTTP(S) URI used to compare the htu
// claim with the request URI (RFC 9449 §4.3): the query and fragment are
// removed, scheme and host are lower-cased, the default port is dropped, an
// empty path becomes "/", and percent-encoding is normalized (hex digits
// upper-cased, unreserved characters decoded) per RFC 3986 §6.2.2 and §6.2.3.
//
// Dot-segment removal is not performed; such URIs simply fail to match.
func NormalizeURI(raw string) (string, error) {
	u, err := url.Parse(raw)
	if err != nil {
		return "", err
	}
	scheme := strings.ToLower(u.Scheme)
	if scheme != "https" && scheme != "http" {
		return "", errors.New("dpop: URI scheme must be http or https")
	}
	if u.Opaque != "" || u.Hostname() == "" {
		return "", errors.New("dpop: URI must be absolute with a host")
	}
	hostname, port := strings.ToLower(u.Hostname()), u.Port()
	if strings.HasPrefix(u.Host, "[") {
		hostname = "[" + hostname + "]"
	} else if strings.Contains(hostname, ":") {
		return "", errors.New("dpop: invalid URI host")
	}
	for i := 0; i < len(port); i++ {
		if port[i] < '0' || port[i] > '9' {
			return "", errors.New("dpop: invalid URI port")
		}
	}
	host := hostname
	if port != "" && !(scheme == "https" && port == "443") && !(scheme == "http" && port == "80") {
		host += ":" + port
	}
	path := normalizePercent(u.EscapedPath())
	if path == "" {
		path = "/"
	}
	return scheme + "://" + host + path, nil
}

func normalizePercent(p string) string {
	if !strings.Contains(p, "%") {
		return p
	}
	const hex = "0123456789ABCDEF"
	var b strings.Builder
	b.Grow(len(p))
	for i := 0; i < len(p); i++ {
		c := p[i]
		if c == '%' && i+2 < len(p) && isHex(p[i+1]) && isHex(p[i+2]) {
			v := unhex(p[i+1])<<4 | unhex(p[i+2])
			if isUnreserved(v) {
				b.WriteByte(v)
			} else {
				b.WriteByte('%')
				b.WriteByte(hex[v>>4])
				b.WriteByte(hex[v&0xF])
			}
			i += 2
			continue
		}
		b.WriteByte(c)
	}
	return b.String()
}

func isHex(c byte) bool {
	return ('0' <= c && c <= '9') || ('a' <= c && c <= 'f') || ('A' <= c && c <= 'F')
}

func unhex(c byte) byte {
	switch {
	case '0' <= c && c <= '9':
		return c - '0'
	case 'a' <= c && c <= 'f':
		return c - 'a' + 10
	default:
		return c - 'A' + 10
	}
}

func isUnreserved(c byte) bool {
	return ('a' <= c && c <= 'z') || ('A' <= c && c <= 'Z') || ('0' <= c && c <= '9') ||
		c == '-' || c == '.' || c == '_' || c == '~'
}
