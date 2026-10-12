// Copyright 2015 Matthew Holt and The Caddy Authors
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
// https://www.apache.org/licenses/LICENSE-2.0
package fileserver

import (
	"context"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"runtime"
	"testing"

	"github.com/caddyserver/caddy/v2"
	"github.com/caddyserver/caddy/v2/internal/filesystems"
	"github.com/caddyserver/caddy/v2/modules/caddyhttp"
)

func TestFileMatcherDefaultGlobEscaping(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("Windows does not permit literal wildcard characters in filenames")
	}
	for _, tc := range []struct{ literal, decoy string }{
		{"star*.txt", "star-decoy.txt"},
		{"question?.txt", "questionX.txt"},
		{"bracket[ab].txt", "bracketa.txt"},
		{`slash\*.txt`, `slash\-decoy.txt`},
	} {
		t.Run(tc.literal, func(t *testing.T) {
			root := t.TempDir()
			if err := os.WriteFile(filepath.Join(root, tc.decoy), nil, 0o600); err != nil {
				t.Fatal(err)
			}
			m := MatchFile{
				fsmap:    &filesystems.FileSystemMap{},
				Root:     root,
				TryFiles: []string{"{http.request.uri.query.missing:-/" + tc.literal + "}"},
			}
			req := httptest.NewRequest(http.MethodGet, "/", nil)
			repl := caddyhttp.NewTestReplacer(req)
			if matched, err := m.MatchWithError(req); err != nil || matched {
				t.Fatalf("literal fallback matched wildcard decoy: (%v, %v)", matched, err)
			}
			if err := os.WriteFile(filepath.Join(root, tc.literal), nil, 0o600); err != nil {
				t.Fatal(err)
			}
			if matched, err := m.MatchWithError(req); err != nil || !matched {
				t.Fatalf("literal wildcard filename did not match: (%v, %v)", matched, err)
			}
			if got, _ := repl.Get("http.matchers.file.relative"); got != "/"+tc.literal {
				t.Errorf("selected file = %v; want /%s", got, tc.literal)
			}
		})
	}
}

func TestFileMatcherCELDefault(t *testing.T) {
	ctx, cancel := caddy.NewContext(caddy.Context{Context: context.Background()})
	defer cancel()
	m := caddyhttp.MatchExpression{Expr: `file({"root":"./testdata", "try_files":[{http.request.uri.query.missing:-/foo.txt}]})`}
	if err := m.Provision(ctx); err != nil {
		t.Fatal(err)
	}
	req := httptest.NewRequest(http.MethodGet, "http://example.com/", nil)
	caddyhttp.NewTestReplacer(req)
	if matched, err := m.MatchWithError(req); err != nil || !matched {
		t.Fatalf("match=(%v,%v); want (true,nil)", matched, err)
	}
}

func TestFileMatcherDefaultsEscapeProviderGlobs(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("Windows does not evaluate glob expressions")
	}
	root := t.TempDir()
	if err := os.WriteFile(filepath.Join(root, "private-decoy.txt"), nil, 0o600); err != nil {
		t.Fatal(err)
	}
	for _, pattern := range []string{
		`{http.request.header.X-File:-/fallback}`,
		`{missing:-{http.request.header.X-File}}`,
		`{missing:-/prefix/../{http.request.header.X-File}}`,
	} {
		req := httptest.NewRequest(http.MethodGet, "/", nil)
		req.Header.Set("X-File", "private*.txt")
		caddyhttp.NewTestReplacer(req)
		m := MatchFile{fsmap: &filesystems.FileSystemMap{}, Root: root, TryFiles: []string{pattern}}
		if matched, err := m.MatchWithError(req); err != nil || matched {
			t.Fatalf("provider wildcard matched decoy with %q: (%v, %v)", pattern, matched, err)
		}
	}
}
