// Copyright 2015 Matthew Holt and The Caddy Authors
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
// https://www.apache.org/licenses/LICENSE-2.0
package rewrite

import (
	"net/http"
	"testing"

	"github.com/caddyserver/caddy/v2/modules/caddyhttp"
)

func TestRewritePlaceholderDefaultQueries(t *testing.T) {
	for _, tc := range []struct {
		name, requestURI, rewriteURI, wantQuery string
	}{
		{"literal spaces", "/orig", "/dest?q={missing:-two words}", "q=two+words"},
		{"literal delimiters", "/orig", "/dest?q={missing:-a b=c?d#e&f}&next=ok", "q=a+b%3Dc%3Fd%23e%26f&next=ok"},
		{"literal delimiters in key", "/orig", "/dest?{missing:-a=b?c#d&f}=ok", "a%3Db%3Fc%23d%26f=ok"},
		{"nested encoded query", "/orig?a=two+words&b=%3F", "/dest?{missing:-{http.request.uri.query}}&next=ok", "a=two+words&b=%3F&next=ok"},
		{"empty query literal fallback", "/orig", "/dest?{http.request.uri.query:-two words=?#}", "two+words%3D%3F%23"},
		{"empty query fallback in value", "/orig", "/dest?q={http.request.uri.query:-two words=?#}", "q=two+words%3D%3F%23"},
		{"nested provider text stays literal", "/orig", "/dest?q={missing:-{http.request.header.X-Literal}}", "q=%7Bdanger%7D"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			req := newRequest(t, http.MethodGet, tc.requestURI)
			req.Header.Set("X-Literal", "{danger}")
			repl := caddyhttp.NewTestReplacer(req)
			repl.Set("danger", "expanded")
			rule := Rewrite{URI: tc.rewriteURI}
			rule.Rewrite(req, repl)
			if req.URL.Path != "/dest" || req.URL.RawQuery != tc.wantQuery || req.URL.Fragment != "" {
				t.Fatalf("rewritten URL = %s; want path /dest, query %q, empty fragment", req.URL, tc.wantQuery)
			}
		})
	}
}

func TestRewritePlaceholderDefaultPathValuesStayLiteral(t *testing.T) {
	for _, uri := range []string{
		"/dest/{http.request.header.X-Literal:-fallback}",
		"/dest/{missing:-{http.request.header.X-Literal}}",
	} {
		t.Run(uri, func(t *testing.T) {
			req := newRequest(t, http.MethodGet, "/orig")
			req.Header.Set("X-Literal", "{danger}")
			repl := caddyhttp.NewTestReplacer(req)
			repl.Set("danger", "expanded")
			rule := Rewrite{URI: uri}
			rule.Rewrite(req, repl)
			if req.URL.Path != "/dest/{danger}" || req.URL.RawQuery != "" || req.URL.Fragment != "" {
				t.Fatalf("rewritten URL = %s; provider text must remain literal", req.URL)
			}
		})
	}
}

func TestRewritePlaceholderDefaultPathDelimiters(t *testing.T) {
	for _, tc := range []struct {
		name, requestURI, rewriteURI, wantPath, wantQuery string
	}{
		{"composite path preserves escaped question mark", "/a%3Fb", "{missing:-/prefix{http.request.uri.path}}", "/prefix/a?b", ""},
		{"literal fallback sets query", "/orig", "{missing:-/home?lang=en}", "/home", "lang=en"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			req := newRequest(t, http.MethodGet, tc.requestURI)
			repl := caddyhttp.NewTestReplacer(req)
			rule := Rewrite{URI: tc.rewriteURI}
			rule.Rewrite(req, repl)
			if req.URL.Path != tc.wantPath || req.URL.RawQuery != tc.wantQuery {
				t.Fatalf("rewritten URL = %s; want path %q and query %q", req.URL, tc.wantPath, tc.wantQuery)
			}
		})
	}
}
