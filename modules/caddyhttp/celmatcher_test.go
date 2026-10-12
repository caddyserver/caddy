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
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"

	"cel.dev/cel-go/common/types"
	"cel.dev/cel-go/common/types/ref"

	"github.com/caddyserver/caddy/v2"
	"github.com/caddyserver/caddy/v2/caddyconfig/caddyfile"
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
			name: "header matches a placeholder replaced during the header matcher (MatchHeader)",
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
			name: "url_pattern matches named group (MatchURLPattern)",
			expression: &MatchExpression{
				Expr: `url_pattern('/books/:id')`,
			},
			urlTarget:  "https://example.com/books/123",
			wantResult: true,
		},
		{
			name: "url_pattern does not match (MatchURLPattern)",
			expression: &MatchExpression{
				Expr: `url_pattern('/books/:id')`,
			},
			urlTarget:  "https://example.com/movies/123",
			wantResult: false,
		},
		{
			name: "url_pattern with base_url matches host (MatchURLPattern)",
			expression: &MatchExpression{
				Expr: `url_pattern('/foo', 'https://example.com')`,
			},
			urlTarget:  "https://example.com/foo",
			wantResult: true,
		},
		{
			name: "url_pattern with base_url rejects other host (MatchURLPattern)",
			expression: &MatchExpression{
				Expr: `url_pattern('/foo', 'https://example.com')`,
			},
			urlTarget:  "https://other.com/foo",
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
			for b.Loop() {
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

func TestMatchExpressionUnmarshalCaddyfileRepeated(t *testing.T) {
	for _, input := range []string{`
		expression {http.request.method} == 'GET'
		expression {http.request.uri.path}.startsWith('/public/')
	`, `
		expression "{http.request.method} == 'GET'"
		expression {http.request.uri.path}.startsWith('/public/')
	`} {
		d := caddyfile.NewTestDispenser(input)
		m := new(MatchExpression)
		err := m.UnmarshalCaddyfile(d)
		if err == nil || !strings.Contains(err.Error(), "repeated expression matchers are not supported") {
			t.Errorf("UnmarshalCaddyfile() error = %v, want repeated expression error (expression: %s)", err, m.Expr)
		}
	}
}

func TestCELMatcherEvaluatedInputsStayLiteral(t *testing.T) {
	t.Setenv("CADDY_CEL_CANARY", "canary")
	t.Setenv("caddy_cel_canary", "canary")
	token := "{env.CADDY_CEL_CANARY}"
	for _, tc := range []struct {
		name, expression, url, source, expected string
		vars                                    map[string]any
		want                                    bool
	}{
		{name: "vars value cannot read env", expression: `vars({'expected': [{http.request.header.X-Source}]})`, source: token, vars: map[string]any{"expected": "canary"}},
		{name: "vars value matches literal", expression: `vars({'expected': [{http.request.header.X-Source}]})`, source: token, vars: map[string]any{"expected": token}, want: true},
		{name: "vars key cannot read env", expression: `vars({{http.request.header.X-Source}: ['canary']})`, source: token},
		{name: "vars key names literal variable", expression: `vars({{http.request.header.X-Source}: ['literal-variable']})`, source: token, vars: map[string]any{token: "literal-variable"}, want: true},
		{name: "vars regexp key literal", expression: `vars_regexp({http.request.header.X-Source}, '^literal-variable$')`, source: token, vars: map[string]any{token: "literal-variable"}, want: true},
		{name: "vars regexp named key literal", expression: `vars_regexp('name', {http.request.header.X-Source}, '^literal-variable$')`, source: token, vars: map[string]any{token: "literal-variable"}, want: true},
		{name: "header value cannot read env", expression: `header({'X-Expected': [{http.request.header.X-Source}]})`, source: token, expected: "canary"},
		{name: "header value matches literal", expression: `header({'X-Expected': [{http.request.header.X-Source}]})`, source: token, expected: token, want: true},
		{name: "header dynamic raw key", expression: `header({{http.request.header.X-Source}: ['canary']})`, source: "X-Expected", expected: "canary", want: true},
		{name: "query value cannot read env", expression: `query({'expected': [{http.request.header.X-Source}]})`, source: token, url: "https://example.com/?expected=canary"},
		{name: "query value literal", expression: `query({'expected': [{http.request.header.X-Source}]})`, source: token, url: "https://example.com/?expected=%7Benv.CADDY_CEL_CANARY%7D", want: true},
		{name: "query key literal", expression: `query({{http.request.header.X-Source}: ['canary']})`, source: token, url: "https://example.com/?%7Benv.CADDY_CEL_CANARY%7D=canary", want: true},
		{name: "host value cannot read env", expression: `host({http.request.header.X-Source})`, source: "{env.caddy_cel_canary}", url: "https://canary/"},
		{name: "path value cannot read env", expression: `path({http.request.header.X-Source})`, source: "/{env.caddy_cel_canary}", url: "https://example.com/canary"},
		{name: "path value literal", expression: `path({http.request.header.X-Source})`, source: "/{env.caddy_cel_canary}", url: "https://example.com/%7Benv.caddy_cel_canary%7D", want: true},
		{name: "configured vars key mixed with dynamic value", expression: `vars({'\{http.request.method}': [{http.request.header.X-Source}]})`, source: "GET", want: true},
		{name: "configured value has same text as dynamic", expression: `vars({'expected': ['\{env.CADDY_CEL_CANARY}', {http.request.header.X-Source}]})`, source: token, vars: map[string]any{"expected": "canary"}, want: true},
		{name: "dynamic concat stays literal", expression: `header({'X-Expected': ['prefix-' + {http.request.header.X-Source}]})`, source: token, expected: "prefix-" + token, want: true},
		{name: "configured concat segment expands", expression: `header({'X-Expected': ['\{http.request.method}-' + {http.request.header.X-Source}]})`, source: token, expected: "GET-" + token, want: true},
		{name: "provider data from configured concat stays literal", expression: `header({'X-Expected': ['\{http.vars.prefix}' + {http.request.header.X-Source}]})`, source: "tail", expected: token + "tail", vars: map[string]any{"prefix": token}, want: true},
		{name: "concat cannot assemble env reference", expression: `header({'X-Expected': ['{' + {http.request.header.X-Source} + '}']})`, source: "env.CADDY_CEL_CANARY", expected: token, want: true},
		{name: "unbalanced runtime open remains literal", expression: `vars({'expected': [{http.request.header.X-Source}]})`, source: "{", vars: map[string]any{"expected": "{"}, want: true},
		{name: "backslash escaped runtime braces preserved", expression: `vars({'expected': [{http.request.header.X-Source}]})`, source: `\{env.CADDY_CEL_CANARY\}`, vars: map[string]any{"expected": `\{env.CADDY_CEL_CANARY\}`}, want: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			ctx, cancel := caddy.NewContext(caddy.Context{Context: context.Background()})
			defer cancel()
			m := MatchExpression{Expr: tc.expression}
			if err := m.Provision(ctx); err != nil {
				t.Fatal(err)
			}
			req, _ := newVarsTestRequest(t, tc.url, http.Header{"X-Source": []string{tc.source}, "X-Expected": []string{tc.expected}}, tc.vars)
			got, err := m.MatchWithError(req)
			if err != nil || got != tc.want {
				t.Fatalf("match=%v err=%v want=%v; expanded=%s", got, err, tc.want, m.expandedExpr)
			}
		})
	}
}

func TestCELMatcherLiteralInputsPreserveBodyErrors(t *testing.T) {
	for _, expression := range []string{`vars({'expected': [{limited}]})`, `header({'X-Expected': [{limited}]})`, `path({limited})`, `header({'X-Expected': ['prefix' + {limited}]})`} {
		t.Run(expression, func(t *testing.T) {
			ctx, cancel := caddy.NewContext(caddy.Context{Context: context.Background()})
			defer cancel()
			m := MatchExpression{Expr: expression}
			if err := m.Provision(ctx); err != nil {
				t.Fatal(err)
			}
			req, repl := newVarsTestRequest(t, "", nil, nil)
			marker := RequestBodyLimitError{Err: &http.MaxBytesError{Limit: 1}}
			repl.Set("limited", marker)
			got, err := m.MatchWithError(req)
			var bodyLimit RequestBodyLimitError
			if got || !errors.As(err, &bodyLimit) {
				t.Fatalf("lost typed body error: match=%v err=%v", got, err)
			}
		})
	}
}

func TestCELMatcherLiteralMapCollision(t *testing.T) {
	value := types.NewRefValMap(types.DefaultTypeAdapter, map[ref.Val]ref.Val{
		types.String("same"): types.String("configured"),
		&celMatcherLiteralString{String: types.String("same")}: types.String("evaluated"),
	})
	if _, err := CELMatcherStringMap(value); err == nil {
		t.Fatal("identical map keys with different provenance must be rejected")
	}
}

func TestCELMatcherLiteralTemplateRoundTrip(t *testing.T) {
	repl := caddy.NewReplacer()
	repl.Set("secret", "expanded-secret")
	for _, input := range []string{
		"{secret}", `\{secret}`, `{secret\}`, `\\{secret}`, "{}{}", "{unclosed", "closed}",
	} {
		value := CELMatcherString{value: input, literal: true}
		if got := repl.ReplaceAll(value.Template(), ""); got != input {
			t.Errorf("literal %q replaced to %q", input, got)
		}
	}
}

// A placeholder can return a collection instead of a scalar string. Its leaves
// are evaluated data, just as if the placeholder had returned one string.
func TestCELMatcherLiteralEvaluatedList(t *testing.T) {
	ctx, cancel := caddy.NewContext(caddy.Context{Context: context.Background()})
	defer cancel()
	matcher := MatchExpression{Expr: `header({'X-Value': {values}})`}
	if err := matcher.Provision(ctx); err != nil {
		t.Fatal(err)
	}
	for _, input := range []any{[]string{"{secret}"}, []any{"{secret}"}} {
		for _, want := range []struct {
			header  string
			matches bool
		}{{"{secret}", true}, {"expanded-secret", false}} {
			req := httptest.NewRequest("GET", "https://example.com/", nil)
			req.Header.Set("X-Value", want.header)
			repl := caddy.NewReplacer()
			repl.Set("values", input)
			repl.Set("secret", "expanded-secret")
			req = req.WithContext(context.WithValue(req.Context(), caddy.ReplacerCtxKey, repl))
			matched, err := matcher.MatchWithError(req)
			if err != nil || matched != want.matches {
				t.Errorf("input %T header %q: matched=%v error=%v; want %v", input, want.header, matched, err, want.matches)
			}
		}
	}
}

func TestCELMatcherLiteralQueryTemplateCollision(t *testing.T) {
	ctx, cancel := caddy.NewContext(caddy.Context{Context: context.Background()})
	defer cancel()
	matcher := MatchExpression{Expr: `query({'\\{key\\}': ['expected'], {dynamic_key}: ['other']})`}
	if err := matcher.Provision(ctx); err != nil {
		t.Fatal(err)
	}
	req := httptest.NewRequest("GET", "https://example.com/?%7Bkey%7D=expected", nil)
	repl := caddy.NewReplacer()
	repl.Set("dynamic_key", "{key}")
	req = req.WithContext(context.WithValue(req.Context(), caddy.ReplacerCtxKey, repl))
	if matched, err := matcher.MatchWithError(req); err == nil {
		t.Fatalf("ambiguous query keys must return an error, matched=%v expanded expression=%s", matched, matcher.expandedExpr)
	}
}

func TestCELMatcherLiteralConcurrentConcat(t *testing.T) {
	ctx, cancel := caddy.NewContext(caddy.Context{Context: context.Background()})
	defer cancel()
	matcher := MatchExpression{Expr: `header({'X-Value': '\{secret}' + {suffix}})`}
	if err := matcher.Provision(ctx); err != nil {
		t.Fatal(err)
	}
	var wg sync.WaitGroup
	for i := 0; i < 16; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			for j := 0; j < 10; j++ {
				secret := fmt.Sprintf("request-%d-%d", i, j)
				req := httptest.NewRequest("GET", "https://example.com/", nil)
				req.Header.Set("X-Value", secret+"{secret}")
				repl := caddy.NewReplacer()
				repl.Set("secret", secret)
				repl.Set("suffix", "{secret}")
				req = req.WithContext(context.WithValue(req.Context(), caddy.ReplacerCtxKey, repl))
				if matched, err := matcher.MatchWithError(req); err != nil || !matched {
					t.Errorf("request %s: matched=%v error=%v", secret, matched, err)
				}
			}
		}(i)
	}
	wg.Wait()
}

func TestCELMatcherLiteralUnsupportedCycles(t *testing.T) {
	ctx, cancel := caddy.NewContext(caddy.Context{Context: context.Background()})
	defer cancel()
	matcher := MatchExpression{Expr: `header({'X-Value': {values}})`}
	if err := matcher.Provision(ctx); err != nil {
		t.Fatal(err)
	}
	cycle := make([]any, 2)
	cycle[0], cycle[1] = cycle, cycle
	req := httptest.NewRequest("GET", "https://example.com/", nil)
	repl := caddy.NewReplacer()
	repl.Set("values", cycle)
	req = req.WithContext(context.WithValue(req.Context(), caddy.ReplacerCtxKey, repl))
	if matched, err := matcher.MatchWithError(req); err == nil || matched {
		t.Fatalf("unsupported cyclic input must be rejected: matched=%v error=%v", matched, err)
	}
}
