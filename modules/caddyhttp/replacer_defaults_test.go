// Copyright 2015 Matthew Holt and The Caddy Authors
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
// https://www.apache.org/licenses/LICENSE-2.0
package caddyhttp

import (
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestHTTPPlaceholderDefaults(t *testing.T) {
	req := httptest.NewRequest(http.MethodGet, "/?present=value&empty=", nil)
	req.Header.Set("X-Present", "value")
	req.Header.Set("X-Literal", "{http.request.method}")
	req.AddCookie(&http.Cookie{Name: "present", Value: "value"})
	repl := NewTestReplacer(req)

	for _, tc := range []struct{ input, want string }{
		{"{http.request.header.X-Missing:-fallback}", "fallback"},
		{"{http.request.header.X-Present:-fallback}", "value"},
		{"{http.request.uri.query.missing:-fallback}", "fallback"},
		{"{http.request.uri.query.empty:-fallback}", "fallback"},
		{"{http.request.uri.query.present:-fallback}", "value"},
		{"{http.request.cookie.missing:-fallback}", "fallback"},
		{"{http.request.cookie.present:-fallback}", "value"},
		{"{http.regexp.unmatched.1:-fallback}", "fallback"},
		{"{http.request.cookie.missing:-{http.request.header.X-Present}}", "value"},
		{"{http.request.header.X-Literal:-fallback}", "{http.request.method}"},
		{"{http.request.cookie.missing:-{http.request.header.X-Literal}}", "{http.request.method}"},
	} {
		t.Run(tc.input, func(t *testing.T) {
			if got := repl.ReplaceAll(tc.input, ""); got != tc.want {
				t.Errorf("ReplaceAll = %q; want %q", got, tc.want)
			}
			if got, err := repl.ReplaceOrErr(tc.input, true, true); err != nil || got != tc.want {
				t.Errorf("ReplaceOrErr = (%q, %v); want (%q, nil)", got, err, tc.want)
			}
		})
	}
}
