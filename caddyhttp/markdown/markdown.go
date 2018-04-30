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

// Package markdown is middleware to render markdown files as HTML
// on-the-fly.
package markdown

import (
	"bytes"
	"mime"
	"net/http"
	"os"
	"path"
	"strconv"
	"strings"
	"sync"
	"text/template"

	"github.com/mholt/caddy/caddyhttp/httpserver"
	"github.com/russross/blackfriday"
)

// Markdown implements a layer of middleware that serves
// markdown as HTML.
type Markdown struct {
	// Server root
	Root string

	// Jail the requests to site root with a mock file system
	FileSys http.FileSystem

	// Next HTTP handler in the chain
	Next httpserver.Handler

	// The list of markdown configurations
	Configs []*Config

	BufPool *sync.Pool // docs: "A Pool must not be copied after first use."
}

// Config stores markdown middleware configurations.
type Config struct {
	// Markdown renderer
	Renderer blackfriday.Renderer

	// Base path to match
	PathScope string

	// List of extensions to consider as markdown files
	Extensions map[string]struct{}

	// List of style sheets to load for each markdown file
	Styles []string

	// List of JavaScript files to load for each markdown file
	Scripts []string

	// The list of index files to try
	IndexFiles []string

	// Template(s) to render with
	Template *template.Template

	// a pair of template's name and its underlying file information
	TemplateFiles map[string]*cachedFileInfo
}

type cachedFileInfo struct {
	path string
	fi   os.FileInfo
}

// ServeHTTP implements the http.Handler interface.
func (md Markdown) ServeHTTP(w http.ResponseWriter, r *http.Request) (int, error) {
	var cfg *Config
	for _, c := range md.Configs {
		if httpserver.Path(r.URL.Path).Matches(c.PathScope) { // not negated
			cfg = c
			break // or goto
		}
	}
	if cfg == nil {
		return md.Next.ServeHTTP(w, r) // exit early
	}

	// We only deal with HEAD/GET
	switch r.Method {
	case http.MethodGet, http.MethodHead:
	default:
		return http.StatusMethodNotAllowed, nil
	}

	// TODO: Deal with dirents variable in new implementation
	var dirents []os.FileInfo

	fpath := r.URL.Path

	// get a buffer from the pool and make a response recorder
	buf := md.BufPool.Get().(*bytes.Buffer)
	buf.Reset()
	defer md.BufPool.Put(buf)

	// only buffer the response when we want to execute markdown
	shouldBuf := func(status int, header http.Header) bool {
		// see if this request matches a markdown extension
		reqExt := path.Ext(fpath)
		for ext := range cfg.Extensions {
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

	// pass request up the chain to let another middleware provide us markdown
	code, err := md.Next.ServeHTTP(rb, r)
	if !rb.Buffered() || code >= 300 || err != nil {
		return code, err
	}

	// At this point we have a supported extension or content type for markdown
	// create an execution context
	ctx := httpserver.NewContextWithHeader(w.Header())
	ctx.Root = md.FileSys
	ctx.Req = r
	ctx.URL = r.URL

	html, err := cfg.Markdown(title(fpath), rb.Buffer.String(), dirents, ctx)
	if err != nil {
		return http.StatusInternalServerError, err
	}

	// copy the buffered header into the real ResponseWriter
	rb.CopyHeader()

	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Header().Set("Content-Length", strconv.Itoa(len(html)))
	w.WriteHeader(http.StatusOK)
	if r.Method == http.MethodGet {
		w.Write(html)
	}

	return 0, nil
}

// TODO: This is not currently used in new implementation, do we need it?
// latest returns the latest time.Time
// func latest(t ...time.Time) time.Time {
// 	var last time.Time

// 	for _, tt := range t {
// 		if tt.After(last) {
// 			last = tt
// 		}
// 	}

// 	return last
// }

// title gives a backup generated title for a page
func title(p string) string {
	return strings.TrimSuffix(path.Base(p), path.Ext(p))
}
