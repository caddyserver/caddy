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

package templates

import (
	"bytes"
	"fmt"
	"io"
	"net/http"
	"strconv"
	"strings"

	"github.com/caddyserver/caddy/v2"
	"github.com/caddyserver/caddy/v2/modules/caddyhttp"
)

func init() {
	caddy.RegisterModule(caddy.Module{
		Name: "http.handlers.templates",
		New:  func() interface{} { return new(Templates) },
	})
}

// Templates is a middleware which execute response bodies as templates.
type Templates struct {
	IncludeRoot string   `json:"include_root,omitempty"`
	MIMETypes   []string `json:"mime_types,omitempty"`
	Delimiters  []string `json:"delimiters,omitempty"`
}

// Provision provisions t.
func (t *Templates) Provision(ctx caddy.Context) error {
	if t.MIMETypes == nil {
		t.MIMETypes = defaultMIMETypes
	}
	return nil
}

// Validate ensures t has a valid configuration.
func (t *Templates) Validate() error {
	if len(t.Delimiters) != 0 && len(t.Delimiters) != 2 {
		return fmt.Errorf("delimiters must consist of exactly two elements: opening and closing")
	}
	return nil
}

func (t *Templates) ServeHTTP(w http.ResponseWriter, r *http.Request, next caddyhttp.Handler) error {
	buf := bufPool.Get().(*bytes.Buffer)
	buf.Reset()
	defer bufPool.Put(buf)

	// shouldBuf determines whether to execute templates on this response,
	// since generally we will not want to execute for images or CSS, etc.
	shouldBuf := func(status int) bool {
		ct := w.Header().Get("Content-Type")
		for _, mt := range t.MIMETypes {
			if strings.Contains(ct, mt) {
				return true
			}
		}
		return false
	}

	rec := caddyhttp.NewResponseRecorder(w, buf, shouldBuf)

	err := next.ServeHTTP(rec, r)
	if err != nil {
		return err
	}
	if !rec.Buffered() {
		return nil
	}

	err = t.executeTemplate(rec, r)
	if err != nil {
		return err
	}

	w.Header().Set("Content-Length", strconv.Itoa(buf.Len()))
	w.Header().Del("Accept-Ranges") // we don't know ranges for dynamically-created content
	w.Header().Del("Last-Modified") // useless for dynamic content since it's always changing

	// we don't know a way to guickly generate etag for dynamic content,
	// but we can convert this to a weak etag to kind of indicate that
	if etag := w.Header().Get("ETag"); etag != "" {
		w.Header().Set("ETag", "W/"+etag)
	}

	w.WriteHeader(rec.Status())
	io.Copy(w, buf)

	return nil
}

// executeTemplate executes the template contained in wb.buf and replaces it with the results.
func (t *Templates) executeTemplate(rr caddyhttp.ResponseRecorder, r *http.Request) error {
	var fs http.FileSystem
	if t.IncludeRoot != "" {
		fs = http.Dir(t.IncludeRoot)
	}

	ctx := &templateContext{
		Root:       fs,
		Req:        r,
		RespHeader: tplWrappedHeader{rr.Header()},
		config:     t,
	}

	err := ctx.executeTemplateInBuffer(r.URL.Path, rr.Buffer())
	if err != nil {
		return caddyhttp.Error(http.StatusInternalServerError, err)
	}

	return nil
}

// virtualResponseWriter is used in virtualized HTTP requests
// that templates may execute.
type virtualResponseWriter struct {
	status int
	header http.Header
	body   *bytes.Buffer
}

func (vrw *virtualResponseWriter) Header() http.Header {
	return vrw.header
}

func (vrw *virtualResponseWriter) WriteHeader(statusCode int) {
	vrw.status = statusCode
}

func (vrw *virtualResponseWriter) Write(data []byte) (int, error) {
	return vrw.body.Write(data)
}

var defaultMIMETypes = []string{
	"text/html",
	"text/plain",
	"text/markdown",
}

// Interface guards
var (
	_ caddy.Provisioner           = (*Templates)(nil)
	_ caddy.Validator             = (*Templates)(nil)
	_ caddyhttp.MiddlewareHandler = (*Templates)(nil)
)
