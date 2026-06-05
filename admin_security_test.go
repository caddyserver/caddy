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
	"errors"
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"
)

func mustParseURL(t *testing.T, raw string) *url.URL {
	t.Helper()
	u, err := url.Parse(raw)
	if err != nil {
		t.Fatalf("invalid URL %q: %v", raw, err)
	}
	return u
}

func TestAdminHandlerOriginAllowed(t *testing.T) {
	tests := []struct {
		name           string
		allowedOrigins []*url.URL
		origin         *url.URL
		want           bool
	}{
		{
			name:           "no allowed origins denies all",
			allowedOrigins: nil,
			origin:         mustParseURL(t, "http://localhost:2019"),
			want:           false,
		},
		{
			name:           "exact host match without scheme constraint",
			allowedOrigins: []*url.URL{{Host: "localhost:2019"}},
			origin:         mustParseURL(t, "http://localhost:2019"),
			want:           true,
		},
		{
			name:           "scheme mismatch denies even when host matches",
			allowedOrigins: []*url.URL{mustParseURL(t, "https://localhost:2019")},
			origin:         mustParseURL(t, "http://localhost:2019"),
			want:           false,
		},
		{
			name:           "scheme match and host match allows",
			allowedOrigins: []*url.URL{mustParseURL(t, "http://localhost:2019")},
			origin:         mustParseURL(t, "http://localhost:2019"),
			want:           true,
		},
		{
			name:           "different host denied",
			allowedOrigins: []*url.URL{mustParseURL(t, "http://localhost:2019")},
			origin:         mustParseURL(t, "http://evil.example.com:2019"),
			want:           false,
		},
		{
			name:           "different port denied (host comparison includes port)",
			allowedOrigins: []*url.URL{mustParseURL(t, "http://localhost:2019")},
			origin:         mustParseURL(t, "http://localhost:2020"),
			want:           false,
		},
		{
			name: "multiple allowed origins, second one matches",
			allowedOrigins: []*url.URL{
				mustParseURL(t, "http://127.0.0.1:2019"),
				mustParseURL(t, "http://localhost:2019"),
			},
			origin: mustParseURL(t, "http://localhost:2019"),
			want:   true,
		},
		{
			name:           "scheme-less allowed entry matches any scheme",
			allowedOrigins: []*url.URL{{Host: "localhost:2019"}},
			origin:         mustParseURL(t, "https://localhost:2019"),
			want:           true,
		},
		{
			// Per RFC 3986 section 3.2.2, host names are case-insensitive.
			name:           "case-sensitive host comparison (potential RFC 3986 deviation)",
			allowedOrigins: []*url.URL{mustParseURL(t, "http://Example.com:8080")},
			origin:         mustParseURL(t, "http://example.com:8080"),
			want:           true,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			h := adminHandler{allowedOrigins: tc.allowedOrigins}
			got := h.originAllowed(tc.origin)
			if got != tc.want {
				t.Errorf("originAllowed(%v) = %v, want %v", tc.origin, got, tc.want)
			}
		})
	}
}

func TestAdminHandlerGetOrigin(t *testing.T) {
	tests := []struct {
		name           string
		originHeader   string
		refererHeader  string
		wantOriginStr  string
		wantNilURL     bool
		wantHost       string
		wantScheme     string
		wantStrippedOK bool
	}{
		{
			name:           "origin header used",
			originHeader:   "https://example.com",
			wantOriginStr:  "https://example.com",
			wantHost:       "example.com",
			wantScheme:     "https",
			wantStrippedOK: true,
		},
		{
			name:           "origin takes priority over referer",
			originHeader:   "https://allowed.com",
			refererHeader:  "https://other.com",
			wantOriginStr:  "https://allowed.com",
			wantHost:       "allowed.com",
			wantScheme:     "https",
			wantStrippedOK: true,
		},
		{
			name:           "fallback to referer when origin missing strips path query and fragment",
			refererHeader:  "https://from-referer.com/some/path?q=1#frag",
			wantOriginStr:  "https://from-referer.com/some/path?q=1#frag",
			wantHost:       "from-referer.com",
			wantScheme:     "https",
			wantStrippedOK: true,
		},
		{
			name:          "malformed origin returns nil URL",
			originHeader:  "http://[invalid",
			wantOriginStr: "http://[invalid",
			wantNilURL:    true,
		},
		{
			name:           "empty origin and referer yields empty URL not nil",
			wantOriginStr:  "",
			wantHost:       "",
			wantScheme:     "",
			wantStrippedOK: true,
		},
		{
			name:           "origin with port retains port in Host",
			originHeader:   "http://localhost:8080/admin?foo=bar",
			wantOriginStr:  "http://localhost:8080/admin?foo=bar",
			wantHost:       "localhost:8080",
			wantScheme:     "http",
			wantStrippedOK: true,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			req := httptest.NewRequest(http.MethodGet, "http://server/load", nil)
			if tc.originHeader != "" {
				req.Header.Set("Origin", tc.originHeader)
			}
			if tc.refererHeader != "" {
				req.Header.Set("Referer", tc.refererHeader)
			}

			h := adminHandler{}
			gotStr, gotURL := h.getOrigin(req)

			if gotStr != tc.wantOriginStr {
				t.Errorf("origin string: got %q, want %q", gotStr, tc.wantOriginStr)
			}
			if tc.wantNilURL {
				if gotURL != nil {
					t.Errorf("expected nil URL for malformed origin, got %v", gotURL)
				}
				return
			}
			if gotURL == nil {
				t.Fatalf("expected non-nil URL, got nil")
			}
			if gotURL.Host != tc.wantHost {
				t.Errorf("host: got %q, want %q", gotURL.Host, tc.wantHost)
			}
			if gotURL.Scheme != tc.wantScheme {
				t.Errorf("scheme: got %q, want %q", gotURL.Scheme, tc.wantScheme)
			}
			if tc.wantStrippedOK {
				if gotURL.Path != "" || gotURL.RawPath != "" || gotURL.RawQuery != "" || gotURL.Fragment != "" || gotURL.RawFragment != "" {
					t.Errorf("expected path/query/fragment to be stripped, got path=%q rawPath=%q query=%q fragment=%q rawFragment=%q",
						gotURL.Path, gotURL.RawPath, gotURL.RawQuery, gotURL.Fragment, gotURL.RawFragment)
				}
			}
		})
	}
}

func TestAdminHandlerCheckOrigin(t *testing.T) {
	allowed := []*url.URL{mustParseURL(t, "http://localhost:2019")}

	tests := []struct {
		name          string
		originHeader  string
		refererHeader string
		wantErr       bool
		wantStatus    int
	}{
		{
			name:         "matching origin returns no error",
			originHeader: "http://localhost:2019",
		},
		{
			name:         "non-matching origin returns 403",
			originHeader: "http://evil.example.com",
			wantErr:      true,
			wantStatus:   http.StatusForbidden,
		},
		{
			name:         "malformed origin returns 403",
			originHeader: "http://[invalid",
			wantErr:      true,
			wantStatus:   http.StatusForbidden,
		},
		{
			name:       "no origin and no referer returns 403",
			wantErr:    true,
			wantStatus: http.StatusForbidden,
		},
		{
			name:          "matching referer is accepted when origin is absent",
			refererHeader: "http://localhost:2019/some/path",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			req := httptest.NewRequest(http.MethodGet, "http://server/load", nil)
			if tc.originHeader != "" {
				req.Header.Set("Origin", tc.originHeader)
			}
			if tc.refererHeader != "" {
				req.Header.Set("Referer", tc.refererHeader)
			}

			h := adminHandler{allowedOrigins: allowed}
			_, err := h.checkOrigin(req)

			if (err != nil) != tc.wantErr {
				t.Fatalf("checkOrigin err = %v, wantErr = %v", err, tc.wantErr)
			}
			if !tc.wantErr {
				return
			}

			var apiErr APIError
			if !errors.As(err, &apiErr) {
				t.Fatalf("expected APIError, got %T: %v", err, err)
			}
			if apiErr.HTTPStatus != tc.wantStatus {
				t.Errorf("HTTPStatus: got %d, want %d", apiErr.HTTPStatus, tc.wantStatus)
			}
		})
	}
}

func TestAdminHandlerCheckHost(t *testing.T) {
	allowed := []*url.URL{
		mustParseURL(t, "http://localhost:2019"),
		mustParseURL(t, "http://127.0.0.1:2019"),
	}

	tests := []struct {
		name       string
		reqHost    string
		wantErr    bool
		wantStatus int
	}{
		{name: "matching host", reqHost: "localhost:2019"},
		{name: "second allowed host matches", reqHost: "127.0.0.1:2019"},
		{name: "non-matching host", reqHost: "evil.example.com", wantErr: true, wantStatus: http.StatusForbidden},
		{name: "host without port denied", reqHost: "localhost", wantErr: true, wantStatus: http.StatusForbidden},
		{name: "wrong port denied", reqHost: "localhost:8080", wantErr: true, wantStatus: http.StatusForbidden},
		{name: "empty host denied", reqHost: "", wantErr: true, wantStatus: http.StatusForbidden},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			req := httptest.NewRequest(http.MethodGet, "http://server/load", nil)
			req.Host = tc.reqHost

			h := adminHandler{allowedOrigins: allowed}
			err := h.checkHost(req)

			if (err != nil) != tc.wantErr {
				t.Fatalf("checkHost err = %v, wantErr = %v", err, tc.wantErr)
			}
			if !tc.wantErr {
				return
			}
			var apiErr APIError
			if !errors.As(err, &apiErr) {
				t.Fatalf("expected APIError, got %T: %v", err, err)
			}
			if apiErr.HTTPStatus != tc.wantStatus {
				t.Errorf("HTTPStatus: got %d, want %d", apiErr.HTTPStatus, tc.wantStatus)
			}
		})
	}
}
