package caddyhttp

import (
	"testing"
)

func TestFirstBytesLookLikeHTTP(t *testing.T) {
	tests := []struct {
		name string
		hdr  []byte
		want bool
	}{
		{name: "GET request", hdr: []byte("GET /"), want: true},
		{name: "HEAD request", hdr: []byte("HEAD "), want: true},
		{name: "POST request", hdr: []byte("POST "), want: true},
		{name: "PUT request", hdr: []byte("PUT /"), want: true},
		{name: "OPTIONS request", hdr: []byte("OPTIO"), want: true},
		{name: "TLS handshake", hdr: []byte{0x16, 0x03, 0x01, 0x00, 0x00}, want: false},
		{name: "random bytes", hdr: []byte{0xff, 0xfe, 0xfd, 0xfc, 0xfb}, want: false},
		{name: "DELETE not matched", hdr: []byte("DELET"), want: false},
		{name: "PATCH not matched", hdr: []byte("PATCH"), want: false},
		{name: "empty-ish 5 bytes", hdr: []byte("     "), want: false},
		{name: "GET without space", hdr: []byte("GET/a"), want: false},
		{name: "lowercase get", hdr: []byte("get /"), want: false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := firstBytesLookLikeHTTP(tt.hdr)
			if got != tt.want {
				t.Errorf("firstBytesLookLikeHTTP(%q) = %v, want %v", tt.hdr, got, tt.want)
			}
		})
	}
}

func TestHTTPRedirectListenerWrapperCaddyModule(t *testing.T) {
	h := HTTPRedirectListenerWrapper{}
	info := h.CaddyModule()
	if info.ID != "caddy.listeners.http_redirect" {
		t.Errorf("CaddyModule().ID = %v, want 'caddy.listeners.http_redirect'", info.ID)
	}
	if info.New == nil {
		t.Fatal("CaddyModule().New is nil")
	}
}
