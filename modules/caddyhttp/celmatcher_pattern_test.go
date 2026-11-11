package caddyhttp

import (
	"context"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"

	"github.com/caddyserver/caddy/v2"
)

func TestCELPatternPlaceholderExpansion(t *testing.T) {
	t.Setenv("CADDY_CEL_PATTERN_TEST", "secret")
	t.Chdir(t.TempDir())
	private := "synthetic.txt"
	if err := os.WriteFile(private, []byte("secret"), 0o600); err != nil {
		t.Fatal(err)
	}
	for _, expr := range []string{
		`header_regexp('Field', {input})`,
		`path_regexp({input})`,
		`vars_regexp('foo', {input})`,
	} {
		t.Run(expr, func(t *testing.T) {
			for _, tc := range []struct {
				name, pattern, actual string
				want                  bool
			}{
				{"env not expanded", "{env.CADDY_CEL_PATTERN_TEST}", "secret", false},
				{"file not expanded", "{file." + private + "}", "secret", false},
				{"placeholder-shaped regex", "{env.CADDY_CEL_PATTERN_TEST}", "{env.CADDY_CEL_PATTERN_TEST}", true},
				{"quantifier preserved", "se{2}cret", "seecret", true},
				{"regexp grammar preserved", "s[e]+cr.t", "secret", true},
			} {
				t.Run(tc.name, func(t *testing.T) {
					ctx, cancel := caddy.NewContext(caddy.Context{Context: context.Background()})
					defer cancel()
					m := MatchExpression{Expr: expr}
					if err := m.Provision(ctx); err != nil {
						t.Fatal(err)
					}
					req := httptest.NewRequest("GET", "http://example.test/"+tc.actual, nil)
					req = req.WithContext(context.WithValue(req.Context(), VarsCtxKey, map[string]any{"foo": tc.actual}))
					repl := NewTestReplacer(req)
					repl.Set("input", tc.pattern)
					req.Header.Set("Field", tc.actual)
					if matched, err := m.MatchWithError(req); err != nil || matched != tc.want {
						t.Fatalf("matched=%v, error=%v; want %v", matched, err, tc.want)
					}
				})
			}
		})
	}

	for _, tc := range []struct {
		name, expr, pattern, actual string
		want                        bool
	}{
		{"static regexp quantifier", `header_regexp('Field', 'se{2}cret')`, "", "seecret", true},
		{"static regexp placeholder shape", `header_regexp('Field', '\{env.CADDY_CEL_PATTERN_TEST}')`, "", "{env.CADDY_CEL_PATTERN_TEST}", true},
		{"static regexp does not expand", `header_regexp('Field', '\{env.CADDY_CEL_PATTERN_TEST}')`, "", "secret", false},
		{"direct CEL placeholder once", `header_regexp('Field', {env.CADDY_CEL_PATTERN_TEST})`, "", "secret", true},
		{"URL env not expanded", `url_pattern({input})`, "/{env.CADDY_CEL_PATTERN_TEST}", "secret", false},
		{"URL file not expanded", `url_pattern({input})`, "/{file." + filepath.ToSlash(private) + "}", "secret", false},
		{"URL wildcard preserved", `url_pattern({input})`, "/sec*", "secret", true},
		{"URL named group preserved", `url_pattern({input})`, "/:id", "secret", true},
		{"URL static grammar", `url_pattern('/sec*')`, "", "secret", true},
		{"URL static placeholder shape", `url_pattern('/\{env.CADDY_CEL_PATTERN_TEST}')`, "", "secret", false},
		{"URL direct CEL placeholder once", `url_pattern('/' + {env.CADDY_CEL_PATTERN_TEST})`, "", "secret", true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			ctx, cancel := caddy.NewContext(caddy.Context{Context: context.Background()})
			defer cancel()
			m := MatchExpression{Expr: tc.expr}
			if err := m.Provision(ctx); err != nil {
				t.Fatal(err)
			}
			req := httptest.NewRequest("GET", "http://example.test/"+tc.actual, nil)
			repl := NewTestReplacer(req)
			repl.Set("input", tc.pattern)
			req.Header.Set("Field", tc.actual)
			if matched, err := m.MatchWithError(req); err != nil || matched != tc.want {
				t.Fatalf("matched=%v, error=%v; want %v", matched, err, tc.want)
			}
		})
	}
}
