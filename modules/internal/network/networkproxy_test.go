package network

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"

	"go.uber.org/zap"

	"github.com/caddyserver/caddy/v2"
)

// TestProxyFromURLPlaceholderHostValidation checks that a network_proxy URL
// which resolves to a value without a host is rejected after placeholders are
// applied. url.Parse accepts both "http://:80" and "/some/path" without
// returning an error, so ProxyFunc has to reject them itself.
func TestProxyFromURLPlaceholderHostValidation(t *testing.T) {
	for i, tc := range []struct {
		name     string
		url      string
		hostRepl string
		wantHost string
		wantErr  bool
	}{
		{
			name:     "port only, no host",
			url:      "http://{proxy.host}:80",
			hostRepl: "",
			wantErr:  true,
		},
		{
			name:     "no scheme or host, path only",
			url:      "{proxy.host}/some/path",
			hostRepl: "",
			wantErr:  true,
		},
		{
			// url.Parse puts the userinfo elsewhere, so Host is still just
			// ":8080" here. The comment above the check doesn't name this
			// form, but it is equally host-less and equally unusable.
			name:     "userinfo but no host",
			url:      "http://user:pass@{proxy.host}:8080",
			hostRepl: "",
			wantErr:  true,
		},
		{
			name:     "host and port",
			url:      "http://{proxy.host}:8080",
			hostRepl: "proxy.example.com",
			wantHost: "proxy.example.com",
			wantErr:  false,
		},
		{
			name:     "host without port",
			url:      "http://{proxy.host}",
			hostRepl: "proxy.example.com",
			wantHost: "proxy.example.com",
			wantErr:  false,
		},
		{
			// Guards against a repair that splits Host on ":" instead of
			// using Hostname(): an IPv6 literal is full of colons and must
			// not be mistaken for a missing host.
			name:     "IPv6 literal with port",
			url:      "http://[{proxy.host}]:8080",
			hostRepl: "::1",
			wantHost: "::1",
			wantErr:  false,
		},
		{
			name:     "IPv6 literal without port",
			url:      "http://[{proxy.host}]",
			hostRepl: "2001:db8::1",
			wantHost: "2001:db8::1",
			wantErr:  false,
		},
	} {
		p := ProxyFromURL{URL: tc.url, logger: zap.NewNop()}

		repl := caddy.NewReplacer()
		repl.Set("proxy.host", tc.hostRepl)

		req := httptest.NewRequest(http.MethodGet, "http://example.com/", nil)
		req = req.WithContext(context.WithValue(req.Context(), caddy.ReplacerCtxKey, repl))

		proxyURL, err := p.ProxyFunc()(req)

		if tc.wantErr {
			if err == nil {
				t.Errorf("Test %d (%s): expected an error for %q but got none (proxy URL: %v)",
					i, tc.name, tc.url, proxyURL)
			}
			if proxyURL != nil {
				t.Errorf("Test %d (%s): expected a nil proxy URL for %q, got %v",
					i, tc.name, tc.url, proxyURL)
			}
			continue
		}

		if err != nil {
			t.Errorf("Test %d (%s): unexpected error for %q: %v", i, tc.name, tc.url, err)
			continue
		}
		if proxyURL == nil {
			t.Errorf("Test %d (%s): expected a proxy URL for %q, got nil", i, tc.name, tc.url)
			continue
		}
		if proxyURL.Hostname() != tc.wantHost {
			t.Errorf("Test %d (%s): expected host %q, got %q",
				i, tc.name, tc.wantHost, proxyURL.Hostname())
		}
	}
}
