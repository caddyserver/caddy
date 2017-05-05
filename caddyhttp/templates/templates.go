// Package templates implements template execution for files to be
// dynamically rendered for the client.
package templates

import (
	"bytes"
	"net/http"
	"net/http/httptest"
	"path"
	"path/filepath"
	"sync"
	"text/template"
	"time"

	"github.com/mholt/caddy/caddyhttp/httpserver"
)

// ServeHTTP implements the httpserver.Handler interface.
func (t Templates) ServeHTTP(w http.ResponseWriter, r *http.Request) (int, error) {
	// TODO: This performs ~15% worse (req/s) than the old method; why?
	// TODO: Need to somehow embed upcoming httpserver.ResponseWriterWrapper
	// into the ResponseRecorder, so it implements the needed interfaces

	for _, rule := range t.Rules {
		if !httpserver.Path(r.URL.Path).Matches(rule.Path) {
			continue
		}

		// check for index files
		fpath := r.URL.Path
		if idx, ok := httpserver.IndexFile(t.FileSys, fpath, rule.IndexFiles); ok {
			fpath = idx
		}

		// check if extension matches
		reqExt := path.Ext(fpath)
		for _, ext := range rule.Extensions {
			if reqExt == ext {
				// get a buffer from the pool and make a response recorder
				buf := t.BufPool.Get().(*bytes.Buffer)
				buf.Reset()
				defer t.BufPool.Put(buf)
				respRec := &httptest.ResponseRecorder{
					HeaderMap: make(http.Header),
					Body:      buf,
				}

				// pass request up the chain to let another middleware provide us the template
				code, err := t.Next.ServeHTTP(respRec, r)
				if code >= 300 {
					return code, err
				}

				// copy the buffered response headers to the real response writer
				for field, val := range respRec.HeaderMap {
					w.Header()[field] = val
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
				parsedTpl, err := tpl.Parse(respRec.Body.String())
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

				modTime, _ := time.Parse(http.TimeFormat, w.Header().Get("Last-Modified"))

				http.ServeContent(w, r, templateName, modTime, bytes.NewReader(buf.Bytes()))

				return http.StatusOK, nil
			}
		}
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
