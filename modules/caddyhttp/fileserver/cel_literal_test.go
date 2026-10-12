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

package fileserver

import (
	"context"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strconv"
	"testing"

	"github.com/caddyserver/caddy/v2"
	"github.com/caddyserver/caddy/v2/modules/caddyhttp"
)

func TestCELFileProviderTextRemainsLiteral(t *testing.T) {
	const token = "{env.CADDY_CEL_FILE_TEST}"
	t.Setenv("CADDY_CEL_FILE_TEST", "expanded-decoy.txt")
	root := t.TempDir()
	for _, name := range []string{token, "expanded-decoy.txt", "prefix" + token, "prefixexpanded-decoy.txt"} {
		if err := os.WriteFile(filepath.Join(root, name), nil, 0o600); err != nil {
			t.Fatal(err)
		}
	}
	for _, tc := range []struct{ name, expr, want string }{
		{"direct", `file({http.request.header.X-File})`, "/" + token},
		{"repeated", `file({http.request.header.X-File}, "/missing")`, "/" + token},
		{"map list", `file({"root": ` + strconv.Quote(root) + `, "try_files": [{http.request.header.X-File}]})`, "/" + token},
		{"concatenation", `file({"root": ` + strconv.Quote(root) + `, "try_files": ["prefix" + {http.request.header.X-File}]})`, "/prefix" + token},
		{"configured template plus provider", `file({"root": ` + strconv.Quote(root) + `, "try_files": ["\{http.vars.prefix}" + {http.request.header.X-File}]})`, "/prefix" + token},
		{"configured template", `file({"root": ` + strconv.Quote(root) + `, "try_files": ["\{env.CADDY_CEL_FILE_TEST}"]})`, "/expanded-decoy.txt"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			req := httptest.NewRequest(http.MethodGet, "/", nil)
			req.Header.Set("X-File", token)
			repl := caddyhttp.NewTestReplacer(req)
			repl.Set("http.vars.root", root)
			repl.Set("http.vars.prefix", "prefix")
			matchCELFile(t, tc.expr, req)
			if got, _ := repl.Get("http.matchers.file.relative"); got != tc.want {
				t.Fatalf("selected file = %q, want %q", got, tc.want)
			}
		})
	}
}

func TestCELFileProviderRootRemainsLiteral(t *testing.T) {
	const token = "{env.CADDY_CEL_ROOT_TEST}"
	t.Setenv("CADDY_CEL_ROOT_TEST", "expanded-decoy")
	parent := t.TempDir()
	for _, name := range []string{token, "expanded-decoy"} {
		root := filepath.Join(parent, name)
		if err := os.Mkdir(root, 0700); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(root, "target.txt"), nil, 0600); err != nil {
			t.Fatal(err)
		}
	}
	root := filepath.Join(parent, token)
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.Header.Set("X-Root", root)
	repl := caddyhttp.NewTestReplacer(req)
	matchCELFile(t, `file({"root": {http.request.header.X-Root}, "try_files": ["target.txt"]})`, req)
	if got, _ := repl.Get("http.matchers.file.absolute"); got != filepath.Join(root, "target.txt") {
		t.Fatalf("selected file = %q, want root %q", got, root)
	}
}

func TestCELFileRawPolicyAndSplitPath(t *testing.T) {
	root := t.TempDir()
	const name = "script{suffix}"
	if err := os.WriteFile(filepath.Join(root, name), nil, 0600); err != nil {
		t.Fatal(err)
	}
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.Header.Set("X-File", name+"/extra")
	req.Header.Set("X-Split", "{suffix}")
	req.Header.Set("X-Policy", "first_exist")
	repl := caddyhttp.NewTestReplacer(req)
	matchCELFile(t, `file({"root": `+strconv.Quote(root)+`, "try_files": [{http.request.header.X-File}], "split_path": [{http.request.header.X-Split}], "try_policy": {http.request.header.X-Policy}})`, req)
	if got, _ := repl.Get("http.matchers.file.relative"); got != "/"+name {
		t.Fatalf("selected file = %q, want %q", got, "/"+name)
	}
	if got, _ := repl.Get("http.matchers.file.remainder"); got != "/extra" {
		t.Fatalf("remainder = %q, want /extra", got)
	}
}

func matchCELFile(t *testing.T, expr string, req *http.Request) {
	t.Helper()
	ctx, cancel := caddy.NewContext(caddy.Context{Context: context.Background()})
	defer cancel()
	m := caddyhttp.MatchExpression{Expr: expr}
	if err := m.Provision(ctx); err != nil {
		t.Fatal(err)
	}
	if matched, err := m.MatchWithError(req); err != nil || !matched {
		t.Fatalf("expression %s: matched=%v, error=%v", expr, matched, err)
	}
}
