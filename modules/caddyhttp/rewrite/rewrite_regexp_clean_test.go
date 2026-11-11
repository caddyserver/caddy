package rewrite

import (
	"net/http"
	"regexp"
	"testing"

	"github.com/caddyserver/caddy/v2"
	"github.com/caddyserver/caddy/v2/modules/caddyhttp"
)

func TestRegexpRewriteCleansBeforeChangingDepth(t *testing.T) {
	const find = `^/public/preserved/(.*)$`
	rewr := Rewrite{PathRegexp: []*regexReplacer{
		{Find: find, Replace: "/allowed/$1", re: regexp.MustCompile(find)},
	}}
	for _, tc := range []struct {
		target, want string
	}{
		{"/public/preserved/public.txt", "/allowed/public.txt"},
		{"/public/preserved/a/b/../../../secret.txt", "/public/secret.txt"},
		{"/public/preserved/a/b/%2e%2e/%2e%2e/%2e%2e/secret.txt", "/public/secret.txt"},
		{"/public/preserved/a/../public.txt", "/allowed/public.txt"},
		{"/public/preserved/a%2Fb", "/allowed/a%2Fb"},
		{"/public/preserved/a//b", "/allowed/a//b"},
		{"/public/preserved/%252e%252e/secret.txt", "/allowed/%252e%252e/secret.txt"},
	} {
		t.Run(tc.target, func(t *testing.T) {
			req := newRequest(t, http.MethodGet, tc.target+"?keep=yes")
			repl := caddy.NewReplacer()
			req = caddyhttp.PrepareRequest(req, repl, nil, nil)
			rewr.Rewrite(req, repl)
			if got := req.URL.RequestURI(); got != tc.want+"?keep=yes" {
				t.Fatalf("rewritten target = %q, want %q", got, tc.want+"?keep=yes")
			}
		})
	}
}
