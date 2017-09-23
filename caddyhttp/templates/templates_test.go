// Copyright 2015 Light Code Labs, LLC
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

package templates

import (
	"bytes"
	"context"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"

	"github.com/mholt/caddy/caddyhttp/httpserver"
	"github.com/mholt/caddy/caddyhttp/staticfiles"
)

func TestTemplates(t *testing.T) {
	siteRoot := "./testdata"
	tmpl := Templates{
		Next: staticfiles.FileServer{Root: http.Dir(siteRoot)},
		Rules: []Rule{
			{
				Extensions: []string{".html"},
				IndexFiles: []string{"index.html"},
				Path:       "/photos",
			},
			{
				Extensions: []string{".html", ".htm"},
				IndexFiles: []string{"index.html", "index.htm"},
				Path:       "/images",
				Delims:     [2]string{"{%", "%}"},
			},
		},
		Root:    siteRoot,
		FileSys: http.Dir(siteRoot),
		BufPool: &sync.Pool{New: func() interface{} { return new(bytes.Buffer) }},
	}

	tmplroot := Templates{
		Next: staticfiles.FileServer{Root: http.Dir(siteRoot)},
		Rules: []Rule{
			{
				Extensions: []string{".html"},
				IndexFiles: []string{"index.html"},
				Path:       "/",
			},
		},
		Root:    siteRoot,
		FileSys: http.Dir(siteRoot),
		BufPool: &sync.Pool{New: func() interface{} { return new(bytes.Buffer) }},
	}

	// Test tmpl on /photos/test.html
	req, err := http.NewRequest("GET", "/photos/test.html", nil)
	if err != nil {
		t.Fatalf("Test: Could not create HTTP request: %v", err)
	}
	req = req.WithContext(context.WithValue(req.Context(), httpserver.OriginalURLCtxKey, *req.URL))

	rec := httptest.NewRecorder()

	tmpl.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("Test: Wrong response code: %d, should be %d", rec.Code, http.StatusOK)
	}

	respBody := rec.Body.String()
	expectedBody := `<!DOCTYPE html><html><head><title>test page</title></head><body><h1>Header title</h1>
</body></html>
`

	if respBody != expectedBody {
		t.Fatalf("Test: the expected body %v is different from the response one: %v", expectedBody, respBody)
	}

	// Test tmpl on /images/img.htm
	req, err = http.NewRequest("GET", "/images/img.htm", nil)
	if err != nil {
		t.Fatalf("Could not create HTTP request: %v", err)
	}
	req = req.WithContext(context.WithValue(req.Context(), httpserver.OriginalURLCtxKey, *req.URL))

	rec = httptest.NewRecorder()

	tmpl.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("Test: Wrong response code: %d, should be %d", rec.Code, http.StatusOK)
	}

	respBody = rec.Body.String()
	expectedBody = `<!DOCTYPE html><html><head><title>img</title></head><body><h1>Header title</h1>
</body></html>
`

	if respBody != expectedBody {
		t.Fatalf("Test: the expected body %v is different from the response one: %v", expectedBody, respBody)
	}

	// Test tmpl on /images/img2.htm
	req, err = http.NewRequest("GET", "/images/img2.htm", nil)
	if err != nil {
		t.Fatalf("Could not create HTTP request: %v", err)
	}
	req = req.WithContext(context.WithValue(req.Context(), httpserver.OriginalURLCtxKey, *req.URL))

	rec = httptest.NewRecorder()

	tmpl.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("Test: Wrong response code: %d, should be %d", rec.Code, http.StatusOK)
	}

	respBody = rec.Body.String()
	expectedBody = `<!DOCTYPE html><html><head><title>img</title></head><body>{{.Include "header.html"}}</body></html>
`

	if respBody != expectedBody {
		t.Fatalf("Test: the expected body %v is different from the response one: %v", expectedBody, respBody)
	}

	// Test tmplroot on /root.html
	req, err = http.NewRequest("GET", "/root.html", nil)
	if err != nil {
		t.Fatalf("Could not create HTTP request: %v", err)
	}
	req = req.WithContext(context.WithValue(req.Context(), httpserver.OriginalURLCtxKey, *req.URL))

	rec = httptest.NewRecorder()

	// register custom function which is used in template
	httpserver.TemplateFuncs["root"] = func() string { return "root" }
	tmplroot.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("Test: Wrong response code: %d, should be %d", rec.Code, http.StatusOK)
	}

	respBody = rec.Body.String()
	expectedBody = `<!DOCTYPE html><html><head><title>root</title></head><body><h1>Header title</h1>
</body></html>
`

	if respBody != expectedBody {
		t.Fatalf("Test: the expected body %v is different from the response one: %v", expectedBody, respBody)
	}
}
