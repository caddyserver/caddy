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

package caddy

import (
	"net/url"
	"testing"
)

// TestAdminHandlerOriginAllowed_CaseInsensitiveHost is the regression
// test for the host allow-list comparison being case-sensitive. Per
// RFC 3986 §3.2.2, host names are case-insensitive.
func TestAdminHandlerOriginAllowed_CaseInsensitiveHost(t *testing.T) {
	mustParse := func(raw string) *url.URL {
		u, err := url.Parse(raw)
		if err != nil {
			t.Fatalf("invalid URL %q: %v", raw, err)
		}
		return u
	}

	cases := []struct {
		name    string
		allowed *url.URL
		origin  *url.URL
	}{
		{
			name:    "allow-list uppercase, origin lowercase",
			allowed: mustParse("http://Example.com:8080"),
			origin:  mustParse("http://example.com:8080"),
		},
		{
			name:    "allow-list lowercase, origin uppercase",
			allowed: mustParse("http://example.com:8080"),
			origin:  mustParse("http://EXAMPLE.com:8080"),
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			h := adminHandler{allowedOrigins: []*url.URL{tc.allowed}}
			if !h.originAllowed(tc.origin) {
				t.Errorf("originAllowed(%v) with allowed %v = false, want true", tc.origin, tc.allowed)
			}
		})
	}
}
