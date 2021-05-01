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
	"net/http"
	"strconv"
	"strings"

	"github.com/caddyserver/caddy/v2"
	"github.com/caddyserver/caddy/v2/modules/caddyhttp"
)

func init() {
	caddy.RegisterModule(Templates{})
}

// Templates is a middleware which executes response bodies as Go templates.
// The syntax is documented in the Go standard library's
// [text/template package](https://golang.org/pkg/text/template/).
//
// ⚠️ Template functions/actions are still experimental, so they are subject to change.
//
// [All Sprig functions](https://masterminds.github.io/sprig/) are supported.
//
// In addition to the standard functions and the Sprig library, Caddy adds
// extra functions and data that are available to a template:
//
// ##### `.Args`
//
// Access arguments passed to this page/context, for example as the result of a `include`.
//
// ```
// {{.Args 0}} // first argument
// ```
//
// ##### `.Cookie`
//
// Gets the value of a cookie by name.
//
// ```
// {{.Cookie "cookiename"}}
// ```
//
// ##### `env`
//
// Gets an environment variable.
//
// ```
// {{env "VAR_NAME"}}
// ```
//
// ##### `placeholder`
//
// Gets an [placeholder variable](/docs/conventions#placeholders).
// The braces (`{}`) have to be omitted.
//
// ```
// {{placeholder "http.request.uri.path"}}
// {{placeholder "http.error.status_code"}}
// ```
//
// ##### `.Host`
//
// Returns the hostname portion (no port) of the Host header of the HTTP request.
//
// ```
// {{.Host}}
// ```
//
// ##### `httpInclude`
//
// Includes the contents of another file by making a virtual HTTP request (also known as a sub-request). The URI path must exist on the same virtual server because the request does not use sockets; instead, the request is crafted in memory and the handler is invoked directly for increased efficiency.
//
// ```
// {{httpInclude "/foo/bar?q=val"}}
// ```
//
// ##### `include`
//
// Includes the contents of another file. Optionally can pass key-value pairs as arguments to be accessed by the included file.
//
// ```
// {{include "path/to/file.html"}}  // no arguments
// {{include "path/to/file.html" "arg1" 2 "value 3"}}  // with arguments
// ```
//
// ##### `listFiles`
//
// Returns a list of the files in the given directory, which is relative to the template context's file root.
//
// ```
// {{listFiles "/mydir"}}
// ```
//
// ##### `markdown`
//
// Renders the given Markdown text as HTML.
//
// ```
// {{markdown "My _markdown_ text"}}
// ```
//
// ##### `.RemoteIP`
//
// Returns the client's IP address.
//
// ```
// {{.RemoteIP}}
// ```
//
// ##### `.Req`
//
// Accesses the current HTTP request, which has various fields, including:
//
//    - `.Method` - the method
//    - `.URL` - the URL, which in turn has component fields (Scheme, Host, Path, etc.)
//    - `.Header` - the header fields
//    - `.Host` - the Host or :authority header of the request
//
// ```
// {{.Req.Header.Get "User-Agent"}}
// ```
//
// ##### `.RespHeader.Add`
//
// Adds a header field to the HTTP response.
//
// ```
// {{.RespHeader.Add "Field-Name" "val"}}
// ```
//
// ##### `.RespHeader.Del`
//
// Deletes a header field on the HTTP response.
//
// ```
// {{.RespHeader.Del "Field-Name"}}
// ```
//
// ##### `.RespHeader.Set`
//
// Sets a header field on the HTTP response, replacing any existing value.
//
// ```
// {{.RespHeader.Set "Field-Name" "val"}}
// ```
//
// ##### `splitFrontMatter`
//
// Splits front matter out from the body. Front matter is metadata that appears at the very beginning of a file or string. Front matter can be in YAML, TOML, or JSON formats:
//
// **TOML** front matter starts and ends with `+++`:
//
// ```
// +++
// template = "blog"
// title = "Blog Homepage"
// sitename = "A Caddy site"
// +++
// ```
//
// **YAML** is surrounded by `---`:
//
// ```
// ---
// template: blog
// title: Blog Homepage
// sitename: A Caddy site
// ---
// ```
//
//
// **JSON** is simply `{` and `}`:
//
// ```
// {
// 	"template": "blog",
// 	"title": "Blog Homepage",
// 	"sitename": "A Caddy site"
// }
// ```
//
// The resulting front matter will be made available like so:
//
// - `.Meta` to access the metadata fields, for example: `{{$parsed.Meta.title}}`
// - `.Body` to access the body after the front matter, for example: `{{markdown $parsed.Body}}`
//
//
// ##### `stripHTML`
//
// Removes HTML from a string.
//
// ```
// {{stripHTML "Shows <b>only</b> text content"}}
// ```
//
type Templates struct {
	// The root path from which to load files. Required if template functions
	// accessing the file system are used (such as include). Default is
	// `{http.vars.root}` if set, or current working directory otherwise.
	FileRoot string `json:"file_root,omitempty"`

	// The MIME types for which to render templates. It is important to use
	// this if the route matchers do not exclude images or other binary files.
	// Default is text/plain, text/markdown, and text/html.
	MIMETypes []string `json:"mime_types,omitempty"`

	// The template action delimiters.
	Delimiters []string `json:"delimiters,omitempty"`
}

// CaddyModule returns the Caddy module information.
func (Templates) CaddyModule() caddy.ModuleInfo {
	return caddy.ModuleInfo{
		ID:  "http.handlers.templates",
		New: func() caddy.Module { return new(Templates) },
	}
}

// Provision provisions t.
func (t *Templates) Provision(ctx caddy.Context) error {
	if t.MIMETypes == nil {
		t.MIMETypes = defaultMIMETypes
	}
	if t.FileRoot == "" {
		t.FileRoot = "{http.vars.root}"
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
	shouldBuf := func(status int, header http.Header) bool {
		ct := header.Get("Content-Type")
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

	rec.Header().Set("Content-Length", strconv.Itoa(buf.Len()))
	rec.Header().Del("Accept-Ranges") // we don't know ranges for dynamically-created content
	rec.Header().Del("Last-Modified") // useless for dynamic content since it's always changing

	// we don't know a way to quickly generate etag for dynamic content,
	// and weak etags still cause browsers to rely on it even after a
	// refresh, so disable them until we find a better way to do this
	rec.Header().Del("Etag")

	return rec.WriteResponse()
}

// executeTemplate executes the template contained in wb.buf and replaces it with the results.
func (t *Templates) executeTemplate(rr caddyhttp.ResponseRecorder, r *http.Request) error {
	var fs http.FileSystem
	if t.FileRoot != "" {
		repl := r.Context().Value(caddy.ReplacerCtxKey).(*caddy.Replacer)
		fs = http.Dir(repl.ReplaceAll(t.FileRoot, "."))
	}

	ctx := &TemplateContext{
		Root:       fs,
		Req:        r,
		RespHeader: WrappedHeader{rr.Header()},
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
