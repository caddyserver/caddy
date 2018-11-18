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

// Package templates implements template execution for files to be
// dynamically rendered for the client.
package templates

import (
	"bytes"
	"mime"
	"net/http"
	"path"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"text/template"
	"time"

	"github.com/mholt/caddy/caddyhttp/httpserver"
)

// ServeHTTP implements the httpserver.Handler interface.
func (t Templates) ServeHTTP(w http.ResponseWriter, r *http.Request) (int, error) {
	// iterate rules, to find first one that matches the request path
	for _, rule := range t.Rules {
		if !httpserver.Path(r.URL.Path).Matches(rule.Path) {
			continue
		}

		fpath := r.URL.Path

		// get a buffer from the pool and make a response recorder
		buf := t.BufPool.Get().(*bytes.Buffer)
		buf.Reset()
		defer t.BufPool.Put(buf)

		// only buffer the response when we want to execute a template
		shouldBuf := func(status int, header http.Header) bool {
			// see if this request matches a template extension
			reqExt := path.Ext(fpath)
			for _, ext := range rule.Extensions {
				if reqExt == "" {
					// request has no extension, so check response Content-Type
					ct := mime.TypeByExtension(ext)
					if ct != "" && strings.Contains(header.Get("Content-Type"), ct) {
						return true
					}
				} else if reqExt == ext {
					return true
				}
			}
			return false
		}

		// prepare a buffer to hold the response, if applicable
		rb := httpserver.NewResponseBuffer(buf, w, shouldBuf)

		// pass request up the chain to let another middleware provide us the template
		code, err := t.Next.ServeHTTP(rb, r)
		if !rb.Buffered() || code >= 300 || err != nil {
			return code, err
		}

		// create a new template
		templateName := filepath.Base(fpath)
		tpl := template.New(templateName)

		// set delimiters
		if rule.Delims != [2]string{} {
			tpl.Delims(rule.Delims[0], rule.Delims[1])
		}

		// add custom functions
		tpl.Funcs(httpserver.TemplateFuncs)

		// parse the template
		parsedTpl, err := tpl.Parse(rb.Buffer.String())
		if err != nil {
			return http.StatusInternalServerError, err
		}

		// create execution context for the template template
		ctx := httpserver.NewContextWithHeader(w.Header())
		ctx.Root = t.FileSys
		ctx.Req = r
		ctx.URL = r.URL

		// execute the template
		buf.Reset()
		err = parsedTpl.Execute(buf, ctx)
		if err != nil {
			return http.StatusInternalServerError, err
		}

		// copy the buffered header into the real ResponseWriter
		rb.CopyHeader()

		// set the actual content length now that the template was executed
		w.Header().Set("Content-Length", strconv.Itoa(buf.Len()))

		// delete the headers related to cache
		w.Header().Del("ETag")
		w.Header().Del("Last-Modified")

		// get the modification time in preparation for http.ServeContent
		modTime, _ := time.Parse(http.TimeFormat, w.Header().Get("Last-Modified"))

		// at last, write the rendered template to the response; make sure to use
		// use the proper status code, since ServeContent hard-codes 2xx codes...
		http.ServeContent(rb.StatusCodeWriter(w), r, templateName, modTime, bytes.NewReader(buf.Bytes()))

		return 0, nil
	}

	return t.Next.ServeHTTP(w, r)
}

// Templates is middleware to render templated files as the HTTP response.
type Templates struct {
	Next    httpserver.Handler
	Rules   []Rule
	Root    string
	FileSys http.FileSystem
	BufPool *sync.Pool // docs: "A Pool must not be copied after first use."
}

// Rule represents a template rule. A template will only execute
// with this rule if the request path matches the Path specified
// and requests a resource with one of the extensions specified.
type Rule struct {
	Path       string
	Extensions []string
	IndexFiles []string
	Delims     [2]string
}
