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

package markdown

import (
	"bytes"
	"net/http"
	"strconv"
	"strings"
	"sync"

	"github.com/russross/blackfriday/v2"

	"github.com/caddyserver/caddy/v2"
	"github.com/caddyserver/caddy/v2/modules/caddyhttp"
)

func init() {
	caddy.RegisterModule(Markdown{})
}

// Markdown is a middleware for rendering a Markdown response body.
type Markdown struct {
}

// CaddyModule returns the Caddy module information.
func (Markdown) CaddyModule() caddy.ModuleInfo {
	return caddy.ModuleInfo{
		ID:  "http.handlers.markdown",
		New: func() caddy.Module { return new(Markdown) },
	}
}

func (m Markdown) ServeHTTP(w http.ResponseWriter, r *http.Request, next caddyhttp.Handler) error {
	buf := bufPool.Get().(*bytes.Buffer)
	buf.Reset()
	defer bufPool.Put(buf)

	shouldBuf := func(status int, header http.Header) bool {
		return strings.HasPrefix(header.Get("Content-Type"), "text/")
	}

	rec := caddyhttp.NewResponseRecorder(w, buf, shouldBuf)

	err := next.ServeHTTP(rec, r)
	if err != nil {
		return err
	}
	if !rec.Buffered() {
		return nil
	}

	caddyhttp.CopyHeader(w.Header(), rec.Header())

	output := blackfriday.Run(buf.Bytes())

	w.Header().Set("Content-Length", strconv.Itoa(len(output)))
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Header().Del("Accept-Ranges") // we don't know ranges for dynamically-created content
	w.Header().Del("Etag")          // don't know a way to quickly generate etag for dynamic content
	w.Header().Del("Last-Modified") // useless for dynamic content since it's always changing

	w.WriteHeader(rec.Status())
	w.Write(output)

	return nil
}

var bufPool = sync.Pool{
	New: func() interface{} {
		return new(bytes.Buffer)
	},
}

// Interface guard
var _ caddyhttp.MiddlewareHandler = (*Markdown)(nil)
