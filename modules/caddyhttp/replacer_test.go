// Copyright 2015 Matthew Holt and The Caddy Authors
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package caddyhttp

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/caddyserver/caddy/v2"
)

func TestHTTPVarReplacement(t *testing.T) {
	req, _ := http.NewRequest("GET", "/", nil)
	repl := caddy.NewReplacer()
	ctx := context.WithValue(req.Context(), caddy.ReplacerCtxKey, repl)
	req = req.WithContext(ctx)
	req.Host = "example.com:80"
	req.RemoteAddr = "localhost:1234"

	clientCert := []byte(`-----BEGIN CERTIFICATE-----
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

	block, _ := pem.Decode(clientCert)
	if block == nil {
		t.Fatalf("failed to decode PEM certificate")
	}

	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		t.Fatalf("failed to decode PEM certificate: %v", err)
	}

	req.TLS = &tls.ConnectionState{
		Version:                    tls.VersionTLS13,
		HandshakeComplete:          true,
		ServerName:                 "foo.com",
		CipherSuite:                tls.TLS_AES_256_GCM_SHA384,
		PeerCertificates:           []*x509.Certificate{cert},
		NegotiatedProtocol:         "h2",
		NegotiatedProtocolIsMutual: true,
	}

	res := httptest.NewRecorder()
	addHTTPVarsToReplacer(repl, req, res)

	for i, tc := range []struct {
		input  string
		expect string
	}{
		{
			input:  "{http.request.scheme}",
			expect: "https",
		},
		{
			input:  "{http.request.host}",
			expect: "example.com",
		},
		{
			input:  "{http.request.port}",
			expect: "80",
		},
		{
			input:  "{http.request.hostport}",
			expect: "example.com:80",
		},
		{
			input:  "{http.request.remote.host}",
			expect: "localhost",
		},
		{
			input:  "{http.request.remote.port}",
			expect: "1234",
		},
		{
			input:  "{http.request.host.labels.0}",
			expect: "com",
		},
		{
			input:  "{http.request.host.labels.1}",
			expect: "example",
		},
		{
			input:  "{http.request.host.labels.2}",
			expect: "<empty>",
		},
		{
			input:  "{http.request.tls.cipher_suite}",
			expect: "TLS_AES_256_GCM_SHA384",
		},
		{
			input:  "{http.request.tls.proto}",
			expect: "h2",
		},
		{
			input:  "{http.request.tls.proto_mutual}",
			expect: "true",
		},
		{
			input:  "{http.request.tls.resumed}",
			expect: "false",
		},
		{
			input:  "{http.request.tls.server_name}",
			expect: "foo.com",
		},
		{
			input:  "{http.request.tls.version}",
			expect: "tls1.3",
		},
		{
			input:  "{http.request.tls.client.fingerprint}",
			expect: "9f57b7b497cceacc5459b76ac1c3afedbc12b300e728071f55f84168ff0f7702",
		},
		{
			input:  "{http.request.tls.client.issuer}",
			expect: "CN=Caddy Test CA",
		},
		{
			input:  "{http.request.tls.client.serial}",
			expect: "2",
		},
		{
			input:  "{http.request.tls.client.subject}",
			expect: "CN=client.localdomain",
		},
		{
			input:  "{http.request.tls.client.san.dns_names}",
			expect: "[localhost]",
		},
		{
			input:  "{http.request.tls.client.san.dns_names.0}",
			expect: "localhost",
		},
		{
			input:  "{http.request.tls.client.san.dns_names.1}",
			expect: "<empty>",
		},
		{
			input:  "{http.request.tls.client.san.ips}",
			expect: "[127.0.0.1]",
		},
		{
			input:  "{http.request.tls.client.san.ips.0}",
			expect: "127.0.0.1",
		},
		{
			input:  "{http.request.tls.client.certificate_pem}",
			expect: string(clientCert) + "\n", // returned value comes with a newline appended to it
		},
	} {
		actual := repl.ReplaceAll(tc.input, "<empty>")
		if actual != tc.expect {
			t.Errorf("Test %d: Expected placeholder %s to be '%s' but got '%s'",
				i, tc.input, tc.expect, actual)
		}
	}
}
