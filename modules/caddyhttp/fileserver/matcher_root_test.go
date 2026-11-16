package fileserver

import (
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/caddyserver/caddy/v2/internal/filesystems"
	"github.com/caddyserver/caddy/v2/modules/caddyhttp"
	"github.com/caddyserver/caddy/v2/modules/caddyhttp/rewrite"
)

func TestFileMatcherRootRelative(t *testing.T) {
	dir := t.TempDir()
	t.Chdir(dir)
	if err := os.Mkdir("public", 0o700); err != nil {
		t.Fatal(err)
	}
	for _, root := range []string{"", ".", "./", "public", dir, filepath.VolumeName(dir) + string(filepath.Separator)} {
		t.Run(root, func(t *testing.T) {
			// The filesystem root case still writes only inside the temporary directory.
			base := root
			if base == "" {
				base = "."
			}
			prefix := ""
			if root == filepath.VolumeName(dir)+string(filepath.Separator) {
				relative, err := filepath.Rel(root, dir)
				if err != nil {
					t.Fatal(err)
				}
				prefix = filepath.ToSlash(relative) + "/"
			}
			for _, name := range []string{"private.txt", ".private", "missing"} {
				path := prefix + name
				if name != "missing" {
					if err := os.WriteFile(filepath.Join(base, filepath.FromSlash(path)), []byte("synthetic"), 0o600); err != nil {
						t.Fatal(err)
					}
				}
				policy := tryPolicyFirstExist
				if name == "missing" {
					policy = tryPolicyFirstExistFallback
				}
				m := MatchFile{
					fsmap: &filesystems.FileSystemMap{}, Root: root,
					TryFiles: []string{path}, TryPolicy: policy,
				}
				req := httptest.NewRequest(http.MethodGet, "/"+path, nil)
				repl := caddyhttp.NewTestReplacer(req)
				matched, err := m.MatchWithError(req)
				if err != nil || !matched {
					t.Fatalf("matching %q: matched=%v, error=%v", path, matched, err)
				}
				want := "/" + path
				if got, _ := repl.Get("http.matchers.file.relative"); got != want {
					t.Fatalf("relative path = %q, want %q", got, want)
				}
				rewrite.Rewrite{URI: "{http.matchers.file.relative}"}.Rewrite(req, repl)
				if !(caddyhttp.MatchPath{strings.ToLower(want)}).Match(req) {
					t.Fatalf("rewritten path %q bypassed downstream path guard %q", req.URL.Path, want)
				}
			}
		})
	}
}
