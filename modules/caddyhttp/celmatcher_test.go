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
	"net/http/httptest"
	"testing"

	"github.com/caddyserver/caddy/v2"
)

func TestMatchExpressionProvision(t *testing.T) {
	tests := []struct {
		name       string
		expression *MatchExpression
		wantErr    bool
	}{
		{
			name: "boolean matches succeed",
			expression: &MatchExpression{
				Expr: "{http.request.uri.query} != ''",
			},
			wantErr: false,
		},
		{
			name: "reject expressions with non-boolean results",
			expression: &MatchExpression{
				Expr: "{http.request.uri.query}",
			},
			wantErr: true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if err := tt.expression.Provision(caddy.Context{}); (err != nil) != tt.wantErr {
				t.Errorf("MatchExpression.Provision() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}

func TestMatchExpressionMatch(t *testing.T) {

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

	tests := []struct {
		name              string
		expression        *MatchExpression
		wantErr           bool
		wantResult        bool
		clientCertificate []byte
	}{
		{
			name: "boolean matches succeed for placeholder http.request.tls.client.subject",
			expression: &MatchExpression{
				Expr: "{http.request.tls.client.subject} == 'CN=client.localdomain'",
			},
			clientCertificate: clientCert,
			wantResult:        true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if err := tt.expression.Provision(caddy.Context{}); (err != nil) != tt.wantErr {
				t.Errorf("MatchExpression.Provision() error = %v, wantErr %v", err, tt.wantErr)
			}

			req := httptest.NewRequest("GET", "https://example.com/foo", nil)
			repl := caddy.NewReplacer()
			ctx := context.WithValue(req.Context(), caddy.ReplacerCtxKey, repl)
			req = req.WithContext(ctx)
			addHTTPVarsToReplacer(repl, req, httptest.NewRecorder())

			if tt.clientCertificate != nil {
				block, _ := pem.Decode(clientCert)
				if block == nil {
					t.Fatalf("failed to decode PEM certificate")
				}

				cert, err := x509.ParseCertificate(block.Bytes)
				if err != nil {
					t.Fatalf("failed to decode PEM certificate: %v", err)
				}

				req.TLS = &tls.ConnectionState{
					PeerCertificates: []*x509.Certificate{cert},
				}
			}

			if tt.expression.Match(req) != tt.wantResult {
				t.Errorf("MatchExpression.Match() expected to return '%t', for expression : '%s'", tt.wantResult, tt.expression)
			}

		})
	}
}
