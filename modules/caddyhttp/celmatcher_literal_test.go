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
	"errors"
	"net/http"
	"testing"

	"github.com/caddyserver/caddy/v2"
)

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
