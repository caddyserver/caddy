//go:build go1.27

package caddyhttp

import (
	"context"
	"crypto/tls"
	"encoding/pem"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/caddyserver/caddy/v2"
)

func TestTLSServerCertPlaceholders(t *testing.T) {
	certPEM := []byte(`-----BEGIN CERTIFICATE-----
MIIB9jCCAV+gAwIBAgIBAjANBgkqhkiG9w0BAQsFADAYMRYwFAYDVQQDDA1DYWRk
eSBUZXN0IENBMB4XDTE4MDcyNDIxMzUwNVoXDTI4MDcyMTIxMzUwNVowHTEbMBkG
A1UEAwwSY2xpZW50LmxvY2FsZG9tYWluMIGfMA0GCSqGSIb3DQEBAQUAA4GNADCB
iQKBgQDFDEpzF0ew68teT3xDzcUxVFaTII+jXH1ftHXxxP4BEYBU4q90qzeKFneF
z83I0nC0WAQ45ZwHfhLMYHFzHPdxr6+jkvKPASf0J2v2HDJuTM1bHBbik5Ls5eq+
fVZDP8o/VHKSBKxNs8Goc2NTsr5b07QTIpkRStQK+RJALk4x9QIDAQABo0swSTAJ
BgNVHRMEAjAAMAsGA1UdDwQEAwIHgDAaBgNVHREEEzARgglsb2NhbGhvc3SHBH8A
AAEwEwYDVR0lBAwwCgYIKwYBBQUHAwIwDQYJKoZIhvcNAQELBQADgYEANSjz2Sk+
eqp31wM9il1n+guTNyxJd+FzVAH+hCZE5K+tCgVDdVFUlDEHHbS/wqb2PSIoouLV
3Q9fgDkiUod+uIK0IynzIKvw+Cjg+3nx6NQ0IM0zo8c7v398RzB4apbXKZyeeqUH
9fNwfEi+OoXR6s+upSKobCmLGLGi9Na5s5g=
-----END CERTIFICATE-----`)

	block, _ := pem.Decode(certPEM)
	if block == nil {
		t.Fatalf("failed to decode PEM certificate")
	}

	req := httptest.NewRequest(http.MethodGet, "https://example.com/", nil)
	repl := caddy.NewReplacer()
	ctx := context.WithValue(req.Context(), caddy.ReplacerCtxKey, repl)
	ctx = context.WithValue(ctx, VarsCtxKey, make(map[string]any))
	req = req.WithContext(ctx)

	req.TLS = &tls.ConnectionState{
		Version:           tls.VersionTLS13,
		HandshakeComplete: true,
		ServerName:        "example.com",
		CipherSuite:       tls.TLS_AES_256_GCM_SHA384,
		LocalCertificate:  [][]byte{block.Bytes},
	}

	addHTTPVarsToReplacer(repl, req, nil)

	for i, tc := range []struct {
		get    string
		expect string
	}{
		{
			get:    "http.request.tls.server.fingerprint",
			expect: "9f57b7b497cceacc5459b76ac1c3afedbc12b300e728071f55f84168ff0f7702",
		},
		{
			get:    "http.request.tls.server.issuer",
			expect: "CN=Caddy Test CA",
		},
		{
			get:    "http.request.tls.server.serial",
			expect: "2",
		},
		{
			get:    "http.request.tls.server.subject",
			expect: "CN=client.localdomain",
		},
		{
			get:    "http.request.tls.server.san.dns_names",
			expect: "[localhost]",
		},
		{
			get:    "http.request.tls.server.san.dns_names.0",
			expect: "localhost",
		},
		{
			get:    "http.request.tls.server.san.dns_names.1",
			expect: "",
		},
		{
			get:    "http.request.tls.server.san.ips",
			expect: "[127.0.0.1]",
		},
		{
			get:    "http.request.tls.server.san.ips.0",
			expect: "127.0.0.1",
		},
		{
			get:    "http.request.tls.server.certificate_pem",
			expect: string(certPEM) + "\n",
		},
	} {
		actual, got := repl.GetString(tc.get)
		if !got {
			t.Errorf("Test %d: Expected to recognize placeholder %s", i, tc.get)
		}
		if actual != tc.expect {
			t.Errorf("Test %d: Expected %s to be '%s' but got '%s'", i, tc.get, tc.expect, actual)
		}
	}
}
