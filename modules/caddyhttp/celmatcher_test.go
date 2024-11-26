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

var (
	clientCert = []byte(`-----BEGIN CERTIFICATE-----
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

	matcherTests = []struct {
		name              string
		expression        *MatchExpression
		urlTarget         string
		httpMethod        string
		httpHeader        *http.Header
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
			urlTarget:         "https://example.com/foo",
			wantResult:        true,
		},
		{
			name: "header matches (MatchHeader)",
			expression: &MatchExpression{
				Expr: `header({'Field': 'foo'})`,
			},
			urlTarget:  "https://example.com/foo",
			httpHeader: &http.Header{"Field": []string{"foo", "bar"}},
			wantResult: true,
		},
		{
			name: "header matches an escaped placeholder value (MatchHeader)",
			expression: &MatchExpression{
				Expr: `header({'Field': '\\\{foobar}'})`,
			},
			urlTarget:  "https://example.com/foo",
			httpHeader: &http.Header{"Field": []string{"{foobar}"}},
			wantResult: true,
		},
		{
			name: "header matches an placeholder replaced during the header matcher (MatchHeader)",
			expression: &MatchExpression{
				Expr: `header({'Field': '\{http.request.uri.path}'})`,
			},
			urlTarget:  "https://example.com/foo",
			httpHeader: &http.Header{"Field": []string{"/foo"}},
			wantResult: true,
		},
		{
			name: "header error, invalid escape sequence (MatchHeader)",
			expression: &MatchExpression{
				Expr: `header({'Field': '\\{foobar}'})`,
			},
			wantErr: true,
		},
		{
			name: "header error, needs to be JSON syntax with field as key (MatchHeader)",
			expression: &MatchExpression{
				Expr: `header('foo')`,
			},
			wantErr: true,
		},
		{
			name: "header_regexp matches (MatchHeaderRE)",
			expression: &MatchExpression{
				Expr: `header_regexp('Field', 'fo{2}')`,
			},
			urlTarget:  "https://example.com/foo",
			httpHeader: &http.Header{"Field": []string{"foo", "bar"}},
			wantResult: true,
		},
		{
			name: "header_regexp matches with name (MatchHeaderRE)",
			expression: &MatchExpression{
				Expr: `header_regexp('foo', 'Field', 'fo{2}')`,
			},
			urlTarget:  "https://example.com/foo",
			httpHeader: &http.Header{"Field": []string{"foo", "bar"}},
			wantResult: true,
		},
		{
			name: "header_regexp does not match (MatchHeaderRE)",
			expression: &MatchExpression{
				Expr: `header_regexp('foo', 'Nope', 'fo{2}')`,
			},
			urlTarget:  "https://example.com/foo",
			httpHeader: &http.Header{"Field": []string{"foo", "bar"}},
			wantResult: false,
		},
		{
			name: "header_regexp error (MatchHeaderRE)",
			expression: &MatchExpression{
				Expr: `header_regexp('foo')`,
			},
			wantErr: true,
		},
		{
			name: "host matches localhost (MatchHost)",
			expression: &MatchExpression{
				Expr: `host('localhost')`,
			},
			urlTarget:  "http://localhost",
			wantResult: true,
		},
		{
			name: "host matches (MatchHost)",
			expression: &MatchExpression{
				Expr: `host('*.example.com')`,
			},
			urlTarget:  "https://foo.example.com",
			wantResult: true,
		},
		{
			name: "host does not match (MatchHost)",
			expression: &MatchExpression{
				Expr: `host('example.net', '*.example.com')`,
			},
			urlTarget:  "https://foo.example.org",
			wantResult: false,
		},
		{
			name: "host error (MatchHost)",
			expression: &MatchExpression{
				Expr: `host(80)`,
			},
			wantErr: true,
		},
		{
			name: "method does not match (MatchMethod)",
			expression: &MatchExpression{
				Expr: `method('PUT')`,
			},
			urlTarget:  "https://foo.example.com",
			httpMethod: "GET",
			wantResult: false,
		},
		{
			name: "method matches (MatchMethod)",
			expression: &MatchExpression{
				Expr: `method('DELETE', 'PUT', 'POST')`,
			},
			urlTarget:  "https://foo.example.com",
			httpMethod: "PUT",
			wantResult: true,
		},
		{
			name: "method error not enough arguments (MatchMethod)",
			expression: &MatchExpression{
				Expr: `method()`,
			},
			wantErr: true,
		},
		{
			name: "path matches substring (MatchPath)",
			expression: &MatchExpression{
				Expr: `path('*substring*')`,
			},
			urlTarget:  "https://example.com/foo/substring/bar.txt",
			wantResult: true,
		},
		{
			name: "path does not match (MatchPath)",
			expression: &MatchExpression{
				Expr: `path('/foo')`,
			},
			urlTarget:  "https://example.com/foo/bar",
			wantResult: false,
		},
		{
			name: "path matches end url fragment (MatchPath)",
			expression: &MatchExpression{
				Expr: `path('/foo')`,
			},
			urlTarget:  "https://example.com/FOO",
			wantResult: true,
		},
		{
			name: "path matches end fragment with substring prefix (MatchPath)",
			expression: &MatchExpression{
				Expr: `path('/foo*')`,
			},
			urlTarget:  "https://example.com/FOOOOO",
			wantResult: true,
		},
		{
			name: "path matches one of multiple (MatchPath)",
			expression: &MatchExpression{
				Expr: `path('/foo', '/foo/*', '/bar', '/bar/*', '/baz', '/baz*')`,
			},
			urlTarget:  "https://example.com/foo",
			wantResult: true,
		},
		{
			name: "path_regexp with empty regex matches empty path (MatchPathRE)",
			expression: &MatchExpression{
				Expr: `path_regexp('')`,
			},
			urlTarget:  "https://example.com/",
			wantResult: true,
		},
		{
			name: "path_regexp with slash regex matches empty path (MatchPathRE)",
			expression: &MatchExpression{
				Expr: `path_regexp('/')`,
			},
			urlTarget:  "https://example.com/",
			wantResult: true,
		},
		{
			name: "path_regexp matches end url fragment (MatchPathRE)",
			expression: &MatchExpression{
				Expr: `path_regexp('^/foo')`,
			},
			urlTarget:  "https://example.com/foo/",
			wantResult: true,
		},
		{
			name: "path_regexp does not match fragment at end (MatchPathRE)",
			expression: &MatchExpression{
				Expr: `path_regexp('bar_at_start', '^/bar')`,
			},
			urlTarget:  "https://example.com/foo/bar",
			wantResult: false,
		},
		{
			name: "protocol matches (MatchProtocol)",
			expression: &MatchExpression{
				Expr: `protocol('HTTPs')`,
			},
			urlTarget:  "https://example.com",
			wantResult: true,
		},
		{
			name: "protocol does not match (MatchProtocol)",
			expression: &MatchExpression{
				Expr: `protocol('grpc')`,
			},
			urlTarget:  "https://example.com",
			wantResult: false,
		},
		{
			name: "protocol invocation error no args (MatchProtocol)",
			expression: &MatchExpression{
				Expr: `protocol()`,
			},
			wantErr: true,
		},
		{
			name: "protocol invocation error too many args (MatchProtocol)",
			expression: &MatchExpression{
				Expr: `protocol('grpc', 'https')`,
			},
			wantErr: true,
		},
		{
			name: "protocol invocation error wrong arg type (MatchProtocol)",
			expression: &MatchExpression{
				Expr: `protocol(true)`,
			},
			wantErr: true,
		},
		{
			name: "query does not match against a specific value (MatchQuery)",
			expression: &MatchExpression{
				Expr: `query({"debug": "1"})`,
			},
			urlTarget:  "https://example.com/foo",
			wantResult: false,
		},
		{
			name: "query matches against a specific value (MatchQuery)",
			expression: &MatchExpression{
				Expr: `query({"debug": "1"})`,
			},
			urlTarget:  "https://example.com/foo/?debug=1",
			wantResult: true,
		},
		{
			name: "query matches against multiple values (MatchQuery)",
			expression: &MatchExpression{
				Expr: `query({"debug": ["0", "1", {http.request.uri.query.debug}+"1"]})`,
			},
			urlTarget:  "https://example.com/foo/?debug=1",
			wantResult: true,
		},
		{
			name: "query matches against a wildcard (MatchQuery)",
			expression: &MatchExpression{
				Expr: `query({"debug": ["*"]})`,
			},
			urlTarget:  "https://example.com/foo/?debug=something",
			wantResult: true,
		},
		{
			name: "query matches against a placeholder value (MatchQuery)",
			expression: &MatchExpression{
				Expr: `query({"debug": {http.request.uri.query.debug}})`,
			},
			urlTarget:  "https://example.com/foo/?debug=1",
			wantResult: true,
		},
		{
			name: "query error bad map key type (MatchQuery)",
			expression: &MatchExpression{
				Expr: `query({1: "1"})`,
			},
			wantErr: true,
		},
		{
			name: "query error typed struct instead of map (MatchQuery)",
			expression: &MatchExpression{
				Expr: `query(Message{field: "1"})`,
			},
			wantErr: true,
		},
		{
			name: "query error bad map value type (MatchQuery)",
			expression: &MatchExpression{
				Expr: `query({"debug": 1})`,
			},
			wantErr: true,
		},
		{
			name: "query error no args (MatchQuery)",
			expression: &MatchExpression{
				Expr: `query()`,
			},
			wantErr: true,
		},
		{
			name: "remote_ip error no args (MatchRemoteIP)",
			expression: &MatchExpression{
				Expr: `remote_ip()`,
			},
			wantErr: true,
		},
		{
			name: "remote_ip single IP match (MatchRemoteIP)",
			expression: &MatchExpression{
				Expr: `remote_ip('192.0.2.1')`,
			},
			urlTarget:  "https://example.com/foo",
			wantResult: true,
		},
		{
			name: "vars value (VarsMatcher)",
			expression: &MatchExpression{
				Expr: `vars({'foo': 'bar'})`,
			},
			urlTarget:  "https://example.com/foo",
			wantResult: true,
		},
		{
			name: "vars matches placeholder, needs escape (VarsMatcher)",
			expression: &MatchExpression{
				Expr: `vars({'\{http.request.uri.path}': '/foo'})`,
			},
			urlTarget:  "https://example.com/foo",
			wantResult: true,
		},
		{
			name: "vars error wrong syntax (VarsMatcher)",
			expression: &MatchExpression{
				Expr: `vars('foo', 'bar')`,
			},
			wantErr: true,
		},
		{
			name: "vars error no args (VarsMatcher)",
			expression: &MatchExpression{
				Expr: `vars()`,
			},
			wantErr: true,
		},
		{
			name: "vars_regexp value (MatchVarsRE)",
			expression: &MatchExpression{
				Expr: `vars_regexp('foo', 'ba?r')`,
			},
			urlTarget:  "https://example.com/foo",
			wantResult: true,
		},
		{
			name: "vars_regexp value with name (MatchVarsRE)",
			expression: &MatchExpression{
				Expr: `vars_regexp('name', 'foo', 'ba?r')`,
			},
			urlTarget:  "https://example.com/foo",
			wantResult: true,
		},
		{
			name: "vars_regexp matches placeholder, needs escape (MatchVarsRE)",
			expression: &MatchExpression{
				Expr: `vars_regexp('\{http.request.uri.path}', '/fo?o')`,
			},
			urlTarget:  "https://example.com/foo",
			wantResult: true,
		},
		{
			name: "vars_regexp error no args (MatchVarsRE)",
			expression: &MatchExpression{
				Expr: `vars_regexp()`,
			},
			wantErr: true,
		},
	}
)

func TestMatchExpressionMatch(t *testing.T) {
	for _, tst := range matcherTests {
		tc := tst
		t.Run(tc.name, func(t *testing.T) {
			caddyCtx, cancel := caddy.NewContext(caddy.Context{Context: context.Background()})
			defer cancel()
			err := tc.expression.Provision(caddyCtx)
			if err != nil {
				if !tc.wantErr {
					t.Errorf("MatchExpression.Provision() error = %v, wantErr %v", err, tc.wantErr)
				}
				return
			}

			req := httptest.NewRequest(tc.httpMethod, tc.urlTarget, nil)
			if tc.httpHeader != nil {
				req.Header = *tc.httpHeader
			}
			repl := caddy.NewReplacer()
			ctx := context.WithValue(req.Context(), caddy.ReplacerCtxKey, repl)
			ctx = context.WithValue(ctx, VarsCtxKey, map[string]any{
				"foo": "bar",
			})
			req = req.WithContext(ctx)
			addHTTPVarsToReplacer(repl, req, httptest.NewRecorder())

			if tc.clientCertificate != nil {
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

			matches, err := tc.expression.MatchWithError(req)
			if err != nil {
				t.Errorf("MatchExpression.Match() error = %v", err)
			}
			if matches != tc.wantResult {
				t.Errorf("MatchExpression.Match() expected to return '%t', for expression : '%s'", tc.wantResult, tc.expression.Expr)
			}
		})
	}
}

func BenchmarkMatchExpressionMatch(b *testing.B) {
	for _, tst := range matcherTests {
		tc := tst
		if tc.wantErr {
			continue
		}
		b.Run(tst.name, func(b *testing.B) {
			tc.expression.Provision(caddy.Context{})
			req := httptest.NewRequest(tc.httpMethod, tc.urlTarget, nil)
			if tc.httpHeader != nil {
				req.Header = *tc.httpHeader
			}
			repl := caddy.NewReplacer()
			ctx := context.WithValue(req.Context(), caddy.ReplacerCtxKey, repl)
			ctx = context.WithValue(ctx, VarsCtxKey, map[string]any{
				"foo": "bar",
			})
			req = req.WithContext(ctx)
			addHTTPVarsToReplacer(repl, req, httptest.NewRecorder())
			if tc.clientCertificate != nil {
				block, _ := pem.Decode(clientCert)
				if block == nil {
					b.Fatalf("failed to decode PEM certificate")
				}

				cert, err := x509.ParseCertificate(block.Bytes)
				if err != nil {
					b.Fatalf("failed to decode PEM certificate: %v", err)
				}

				req.TLS = &tls.ConnectionState{
					PeerCertificates: []*x509.Certificate{cert},
				}
			}
			b.ResetTimer()
			for i := 0; i < b.N; i++ {
				tc.expression.MatchWithError(req)
			}
		})
	}
}

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
			ctx, cancel := caddy.NewContext(caddy.Context{Context: context.Background()})
			defer cancel()
			if err := tt.expression.Provision(ctx); (err != nil) != tt.wantErr {
				t.Errorf("MatchExpression.Provision() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}
