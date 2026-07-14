package caddyhttp

import (
	"context"
	"crypto/tls"
	"net/http"
	"net/url"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/caddyserver/caddy/v2"
	"github.com/caddyserver/caddy/v2/caddyconfig/caddyfile"
)

func TestURLPatternMatcher(t *testing.T) {
	for _, tc := range []struct {
		name         string
		match        MatchURLPattern
		host         string
		tls          bool
		input        string
		expect       bool
		provisionErr bool
	}{
		{
			name:   "literal path matches",
			match:  MatchURLPattern{Pattern: "/foo"},
			host:   "example.com",
			input:  "/foo",
			expect: true,
		},
		{
			name:   "literal path mismatch",
			match:  MatchURLPattern{Pattern: "/foo"},
			host:   "example.com",
			input:  "/bar",
			expect: false,
		},
		{
			name:   "named group matches",
			match:  MatchURLPattern{Pattern: "/books/:id"},
			host:   "example.com",
			input:  "/books/123",
			expect: true,
		},
		{
			name:   "named group requires segment",
			match:  MatchURLPattern{Pattern: "/books/:id"},
			host:   "example.com",
			input:  "/books",
			expect: false,
		},
		{
			name:   "wildcard spans segments",
			match:  MatchURLPattern{Pattern: "/files/*"},
			host:   "example.com",
			input:  "/files/a/b/c",
			expect: true,
		},
		{
			name:   "absolute pattern matches host and scheme",
			match:  MatchURLPattern{Pattern: "https://example.com/foo"},
			host:   "example.com",
			tls:    true,
			input:  "/foo",
			expect: true,
		},
		{
			name:   "absolute pattern rejects scheme mismatch",
			match:  MatchURLPattern{Pattern: "https://example.com/foo"},
			host:   "example.com",
			input:  "/foo",
			expect: false,
		},
		{
			name:   "absolute pattern rejects host mismatch",
			match:  MatchURLPattern{Pattern: "https://example.com/foo"},
			host:   "other.com",
			tls:    true,
			input:  "/foo",
			expect: false,
		},
		{
			name:   "ignore_case matches mixed case",
			match:  MatchURLPattern{Pattern: "/foo", IgnoreCase: true},
			host:   "example.com",
			input:  "/FOO",
			expect: true,
		},
		{
			name:   "case sensitive by default",
			match:  MatchURLPattern{Pattern: "/foo"},
			host:   "example.com",
			input:  "/FOO",
			expect: false,
		},
		{
			name:   "base_url scopes to host",
			match:  MatchURLPattern{Pattern: "/search", BaseURL: "https://example.com"},
			host:   "example.com",
			tls:    true,
			input:  "/search?q=caddy",
			expect: true,
		},
		{
			name:   "base_url rejects other host",
			match:  MatchURLPattern{Pattern: "/search", BaseURL: "https://example.com"},
			host:   "other.com",
			tls:    true,
			input:  "/search",
			expect: false,
		},
		{
			name:         "invalid pattern fails provisioning",
			match:        MatchURLPattern{Pattern: "https://[invalid"},
			provisionErr: true,
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			err := tc.match.Provision(caddy.Context{})
			if tc.provisionErr {
				require.Error(t, err)
				return
			}
			require.NoError(t, err)

			u, err := url.ParseRequestURI(tc.input)
			require.NoError(t, err)

			req := &http.Request{URL: u, Host: tc.host}
			if tc.tls {
				req.TLS = &tls.ConnectionState{}
			}

			actual, err := tc.match.MatchWithError(req)
			require.NoError(t, err)
			assert.Equal(t, tc.expect, actual)
		})
	}
}

func TestURLPatternMatcherUnmarshalCaddyfile(t *testing.T) {
	for _, tc := range []struct {
		name      string
		input     string
		expect    MatchURLPattern
		expectErr bool
	}{
		{
			name:   "pattern only",
			input:  `url_pattern /books/:id`,
			expect: MatchURLPattern{Pattern: "/books/:id"},
		},
		{
			name: "base_url and ignore_case",
			input: `url_pattern /search {
				base_url https://example.com
				ignore_case
			}`,
			expect: MatchURLPattern{Pattern: "/search", BaseURL: "https://example.com", IgnoreCase: true},
		},
		{
			name:      "missing pattern",
			input:     `url_pattern`,
			expectErr: true,
		},
		{
			name: "unknown option",
			input: `url_pattern /foo {
				nope
			}`,
			expectErr: true,
		},
		{
			name: "base_url without value",
			input: `url_pattern /foo {
				base_url
			}`,
			expectErr: true,
		},
		{
			name: "ignore_case with stray arg",
			input: `url_pattern /foo {
				ignore_case yes
			}`,
			expectErr: true,
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var m MatchURLPattern
			err := m.UnmarshalCaddyfile(caddyfile.NewTestDispenser(tc.input))
			if tc.expectErr {
				require.Error(t, err)
				return
			}
			require.NoError(t, err)
			assert.Equal(t, tc.expect, m)
		})
	}
}

// TestURLPatternMatcherGroups checks that captured groups are exposed as
// component-scoped placeholders, mirroring the URLPattern result object.
func TestURLPatternMatcherGroups(t *testing.T) {
	m := MatchURLPattern{Pattern: "/books/:id/chapters/:chapter"}
	require.NoError(t, m.Provision(caddy.Context{}))

	u, err := url.ParseRequestURI("/books/42/chapters/7")
	require.NoError(t, err)

	repl := caddy.NewReplacer()
	ctx := context.WithValue(context.Background(), caddy.ReplacerCtxKey, repl)
	req := (&http.Request{URL: u, Host: "example.com"}).WithContext(ctx)

	ok, err := m.MatchWithError(req)
	require.NoError(t, err)
	require.True(t, ok)

	id, _ := repl.GetString("http.url_pattern.pathname.id")
	assert.Equal(t, "42", id)
	chapter, _ := repl.GetString("http.url_pattern.pathname.chapter")
	assert.Equal(t, "7", chapter)
}

// TestURLPatternMatcherRelative checks that a relative pattern matches the
// request path regardless of the request's host.
func TestURLPatternMatcherRelative(t *testing.T) {
	m := MatchURLPattern{Pattern: "/books/:id"}
	require.NoError(t, m.Provision(caddy.Context{}))

	for _, host := range []string{"example.com", "other.org", "192.0.2.1:8080"} {
		u, err := url.ParseRequestURI("/books/42")
		require.NoError(t, err)

		ok, err := m.MatchWithError(&http.Request{URL: u, Host: host})
		require.NoError(t, err)
		assert.Truef(t, ok, "expected match on host %q", host)
	}
}
