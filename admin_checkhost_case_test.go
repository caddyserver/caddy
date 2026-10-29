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
	"net/http/httptest"
	"net/url"
	"testing"
)

// TestAdminHandlerCheckHostCaseInsensitive is the regression test for the
// Host allow-list comparison being case-sensitive. Per RFC 3986 §3.2.2,
// host names are case-insensitive, and url.Parse does not normalize host
// case, so the comparison must fold case. This mirrors the fix applied to
// originAllowed, where an allowed 'http://Example.com:8080' rejected a
// client Host of 'example.com:8080'.
func TestAdminHandlerCheckHostCaseInsensitive(t *testing.T) {
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
		host    string
		wantErr bool
	}{
		{
			name:    "allow-list uppercase, request Host lowercase",
			allowed: mustParse("http://Example.com:2019"),
			host:    "example.com:2019",
			wantErr: false,
		},
		{
			name:    "allow-list lowercase, request Host uppercase",
			allowed: mustParse("http://example.com:2019"),
			host:    "EXAMPLE.com:2019",
			wantErr: false,
		},
		{
			name:    "default localhost entry, request Host uppercase",
			allowed: mustParse("http://localhost:2019"),
			host:    "LOCALHOST:2019",
			wantErr: false,
		},
		{
			name:    "different host is still rejected",
			allowed: mustParse("http://example.com:2019"),
			host:    "evil.example.org:2019",
			wantErr: true,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			h := adminHandler{allowedOrigins: []*url.URL{tc.allowed}}
			r := httptest.NewRequest("GET", "http://"+tc.host+"/config/", nil)
			err := h.checkHost(r)
			if tc.wantErr && err == nil {
				t.Errorf("checkHost(%q) with allowed %v = nil, want error", tc.host, tc.allowed)
			}
			if !tc.wantErr && err != nil {
				t.Errorf("checkHost(%q) with allowed %v = %v, want nil", tc.host, tc.allowed, err)
			}
		})
	}
}
