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
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"

	"github.com/caddyserver/caddy/v2"
	"github.com/caddyserver/caddy/v2/modules/caddyhttp"
)

func TestFileServerRejectsShortNameInParentComponent(t *testing.T) {
	root := t.TempDir()
	const ordinaryName = "ordinary~name-with-long-suffix.txt"
	if err := os.WriteFile(filepath.Join(root, ordinaryName), []byte("ordinary tilde name"), 0o600); err != nil {
		t.Fatal(err)
	}

	fsrv := FileServer{
		Root:          root,
		CanonicalURIs: new(bool),
	}
	ctx, _ := caddy.NewContext(caddy.Context{Context: context.Background()})
	if err := fsrv.Provision(ctx); err != nil {
		t.Fatal(err)
	}

	err := fsrv.ServeHTTP(
		httptest.NewRecorder(),
		newPrecompressedRequest(t, "/PROTEC~1/this-is-a-long-final-filename.txt"),
		nil,
	)
	var handlerErr caddyhttp.HandlerError
	if !errors.As(err, &handlerErr) {
		t.Fatalf("expected HandlerError, got %v", err)
	}
	if handlerErr.StatusCode != http.StatusBadRequest {
		t.Fatalf("status = %d, want %d", handlerErr.StatusCode, http.StatusBadRequest)
	}

	w := httptest.NewRecorder()
	if err := fsrv.ServeHTTP(w, newPrecompressedRequest(t, "/"+ordinaryName), nil); err != nil {
		t.Fatal(err)
	}
	if w.Code != http.StatusOK {
		t.Fatalf("status = %d, want %d", w.Code, http.StatusOK)
	}
	if got, want := w.Body.String(), "ordinary tilde name"; got != want {
		t.Fatalf("body = %q, want %q", got, want)
	}
}
