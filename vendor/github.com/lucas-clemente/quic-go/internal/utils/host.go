package utils

import (
	"net/url"
	"strings"
)

// HostnameFromAddr determines the hostname in an address string
func HostnameFromAddr(addr string) (string, error) {
	p, err := url.Parse(addr)
	if err != nil {
		return "", err
	}
	h := p.Host

	// copied from https://golang.org/src/net/http/transport.go
	if hasPort(h) {
		h = h[:strings.LastIndex(h, ":")]
	}

	return h, nil
}

// copied from https://golang.org/src/net/http/http.go
func hasPort(s string) bool {
	return strings.LastIndex(s, ":") > strings.LastIndex(s, "]")
}
