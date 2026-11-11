package fileserver

import (
	"context"
	"net/http/httptest"
	"os"
	"path/filepath"
	"runtime"
	"testing"

	"github.com/caddyserver/caddy/v2"
	"github.com/caddyserver/caddy/v2/modules/caddyhttp"
)

func TestCELFileRuntimeLiterals(t *testing.T) {
	root := t.TempDir()
	t.Setenv("CADDY_CEL_FILE_TEST", "secret.txt")
	private := filepath.Join(t.TempDir(), "synthetic.txt")
	if err := os.WriteFile(private, []byte("secret.txt"), 0o600); err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{"secret.txt", "{env.CADDY_CEL_FILE_TEST}", "[s]ecret.txt", "=404"} {
		if err := os.WriteFile(filepath.Join(root, name), []byte("synthetic"), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	literalRoot := filepath.Join(root, "{env.CADDY_CEL_FILE_TEST}-root", "[literal]")
	if err := os.MkdirAll(literalRoot, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(literalRoot, "secret.txt"), []byte("synthetic"), 0o600); err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		name, expr, input, relative string
		want                        bool
	}{
		{"runtime glob", `file({input})`, "/secret*.txt", "", false},
		{"runtime question mark", `file({input})`, "/?ecret.txt", "", false},
		{"runtime bracket glob", `file({input})`, "/[a-z]ecret.txt", "", false},
		{"literal brackets", `file({input})`, "/[s]ecret.txt", "/[s]ecret.txt", true},
		{"literal env placeholder", `file({input})`, "/{env.CADDY_CEL_FILE_TEST}", "/{env.CADDY_CEL_FILE_TEST}", true},
		{"file placeholder", `file({input})`, "/{file." + private + "}", "", false},
		{"literal error code", `file({input})`, "=404", "/=404", true},
		{"runtime concat", `file({input} + '.txt')`, "/secret*", "", false},
		{"runtime map concat", `file({'try_files': [{input} + '.txt']})`, "/secret*", "", false},
		{"runtime list", `file({'try_files': [{input}]})`, "/secret*.txt", "", false},
		{"mixed list static glob", `file({'try_files': [{input}, '/s*.txt']})`, "/missing", "/secret.txt", runtime.GOOS != "windows"},
		{"mixed args static template", `file({input}, '\{env.CADDY_CEL_FILE_TEST}')`, "/missing", "/secret.txt", true},
		{"static placeholder", `file('\{env.CADDY_CEL_FILE_TEST}')`, "", "/secret.txt", true},
		{"static concat", `file('/sec' + 'ret.txt')`, "", "/secret.txt", true},
		{"runtime root", `file({'root': {input}, 'try_files': ['secret.txt']})`, literalRoot, "/secret.txt", true},
		{"empty runtime root default", `file({'root': {input}, 'try_files': ['secret.txt']})`, "", "/secret.txt", true},
		{"largest literal", `file({'try_files': [{input}], 'try_policy': 'largest_size'})`, "/[s]ecret.txt", "/[s]ecret.txt", true},
		{"smallest literal", `file({'try_files': [{input}], 'try_policy': 'smallest_size'})`, "/[s]ecret.txt", "/[s]ecret.txt", true},
		{"recent literal", `file({'try_files': [{input}], 'try_policy': 'most_recently_modified'})`, "/[s]ecret.txt", "/[s]ecret.txt", true},
		{"literal fallback", `file({'try_files': [{input}], 'try_policy': 'first_exist_fallback'})`, "/missing*.txt", "/missing*.txt", true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			ctx, cancel := caddy.NewContext(caddy.Context{Context: context.Background()})
			defer cancel()
			m := caddyhttp.MatchExpression{Expr: tc.expr}
			if err := m.Provision(ctx); err != nil {
				t.Fatal(err)
			}
			req := httptest.NewRequest("GET", "/safe", nil)
			repl := caddyhttp.NewTestReplacer(req)
			repl.Set("http.vars.root", root)
			repl.Set("input", tc.input)
			got, err := m.MatchWithError(req)
			if err != nil || got != tc.want {
				t.Fatalf("matched=%v, error=%v; want %v", got, err, tc.want)
			}
			if got {
				if relative, _ := repl.Get("http.matchers.file.relative"); relative != tc.relative {
					t.Fatalf("relative=%q; want %q", relative, tc.relative)
				}
			}
		})
	}
}
