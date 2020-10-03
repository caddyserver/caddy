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
		{
			input:  "{http.request.tls.client.is_verified}",
			expect: "false",
		},
	} {
		actual := repl.ReplaceAll(tc.input, "<empty>")
		if actual != tc.expect {
			t.Errorf("Test %d: Expected placeholder %s to be '%s' but got '%s'",
				i, tc.input, tc.expect, actual)
		}
	}
}

// Use this command to generate the verified cert again if needed
// `openssl req -newkey rsa:2048 -new -nodes -x509 -days 3650 -keyout key.pem -out cert.pem`
func TestVarsReplaceWithVerifiedCert(t *testing.T) {
	req, _ := http.NewRequest("GET", "/", nil)
	repl := caddy.NewReplacer()
	ctx := context.WithValue(req.Context(), caddy.ReplacerCtxKey, repl)
	req = req.WithContext(ctx)
	req.Host = "example.com:80"
	req.RemoteAddr = "localhost:1234"

	verifiedCert := []byte(`-----BEGIN CERTIFICATE-----
MIIEBzCCAu+gAwIBAgIUF+cy33gANcV/6YSImPgx7o4X+QkwDQYJKoZIhvcNAQEL
BQAwgZIxCzAJBgNVBAYTAklOMRIwEAYDVQQIDAlIWURFUkFCQUQxETAPBgNVBAcM
CEJlZ3VtcGV0MQ4wDAYDVQQKDAVDYWRkeTEOMAwGA1UECwwFQ2FkZHkxGDAWBgNV
BAMMD0dBVVJBViBESEFNRUVKQTEiMCAGCSqGSIb3DQEJARYTZ2RoYW1lZWphQGdt
YWlsLmNvbTAeFw0yMDEwMDEwNzEyMzNaFw0zMDA5MjkwNzEyMzNaMIGSMQswCQYD
VQQGEwJJTjESMBAGA1UECAwJSFlERVJBQkFEMREwDwYDVQQHDAhCZWd1bXBldDEO
MAwGA1UECgwFQ2FkZHkxDjAMBgNVBAsMBUNhZGR5MRgwFgYDVQQDDA9HQVVSQVYg
REhBTUVFSkExIjAgBgkqhkiG9w0BCQEWE2dkaGFtZWVqYUBnbWFpbC5jb20wggEi
MA0GCSqGSIb3DQEBAQUAA4IBDwAwggEKAoIBAQC7/Vh9qj/vk0KJAS334Hsh531M
3tDkvY1S1mXI0/Xkh59AP9HZD2y18IjmwwwwPwS3cswabitd9DvYy5K230Hkmnkv
UTM4PsC8rMRoA2NZl1D1KHEvmiBIixMyVQeyITd6XnrV72TlKtZy78o29xJzmv3U
5Xqm9cizJmUyzzV9UWRAafhSOOdEDthzqdcqF/uuoFGSsnjMcDj6XuYjSY2nokl/
vwXTGHCAvOkX+9GXdrtCYuIOfgU5nH+giCkYsN9e9YCg13PG1hwsxpDPDLPYvJMl
djI+o8U/xkdGnvPmWp9r5hyqW4gzbC72PSZQM6+bQlq7bka7D8cw48HlAm0XAgMB
AAGjUzBRMB0GA1UdDgQWBBQtMRVJXzm6F32dTpajXjFJW5/SVjAfBgNVHSMEGDAW
gBQtMRVJXzm6F32dTpajXjFJW5/SVjAPBgNVHRMBAf8EBTADAQH/MA0GCSqGSIb3
DQEBCwUAA4IBAQCPl8V4vc8vujDDQ8pjGgLVA7JeXEGDbABtXPYnO0ALsgdhJWtu
MGawVjUI402IE/0ffpohGNgXj2LHmml55sbRyFFD4EXMeX7NBm2YYn82oVm7rD+x
oDoNd69Oz6jJPoZDEL/YKo2OXxYGmnc2Q3NfrCqr+XuytMZZQxNLXYcAK30Y6KxF
7aMypwBRCnyrefpUKryWGPeJvYndkUoEee+acH9v3nANLoBqkoWNWfE56d/XlA+I
xu6Qum6tNm1i6oOf+22bWwKxtVaXvW9fXmLjA2L6XVWVQtdo3o1FKUdUs0Ec/WPE
poxsVrsicPcWHN+iYnVVoZm97MD6thAKQJ+N
-----END CERTIFICATE-----`)
	block, _ := pem.Decode(verifiedCert)
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
	placeholder := "{http.request.tls.client.is_verified}"
	actual := repl.ReplaceAll(placeholder, "<empty>")
	expectedValue := "true"
	if actual != expectedValue {
		t.Errorf("Test TestReplaceForVerifiedCert: Expected placeholder %s to be '%s' but got '%s'",
			placeholder, expectedValue, actual)
	}
}
