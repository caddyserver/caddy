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
	"errors"
	"fmt"
	"net/http"
	"strconv"
	"strings"
	"text/template"

	"go.uber.org/zap"

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
// Custom template functions can be registered by creating a plugin module under the `http.handlers.templates.functions.*` namespace that implements the `CustomFunctions` interface.
//
// [All Sprig functions](https://masterminds.github.io/sprig/) are supported.
//
// In addition to the standard functions and the Sprig library, Caddy adds
// extra functions and data that are available to a template:
//
// ##### `.Args`
//
// A slice of arguments passed to this page/context, for example
// as the result of a [`include`](#include).
//
// ```
// {{index .Args 0}} // first argument
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
// As a shortcut, `ph` is an alias for `placeholder`.
//
// ```
// {{ph "http.request.method"}}
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
// Includes the contents of another file, and renders it in-place,
// by making a virtual HTTP request (also known as a sub-request).
// The URI path must exist on the same virtual server because the
// request does not use sockets; instead, the request is crafted in
// memory and the handler is invoked directly for increased efficiency.
//
// ```
// {{httpInclude "/foo/bar?q=val"}}
// ```
//
// ##### `import`
//
// Reads and returns the contents of another file, and parses it
// as a template, adding any template definitions to the template
// stack. If there are no definitions, the filepath will be the
// definition name. Any `{{ define }}` blocks will be accessible by
// `{{ template }}` or `{{ block }}`. Imports must happen before the
// template or block action is called. Note that the contents are
// NOT escaped, so you should only import trusted template files.
//
// **filename.html**
// ```
// {{ define "main" }}
// content
// {{ end }}
// ```
//
// **index.html**
// ```
// {{ import "/path/to/filename.html" }}
// {{ template "main" }}
// ```
//
// ##### `include`
//
// Includes the contents of another file, rendering it in-place.
// Optionally can pass key-value pairs as arguments to be accessed
// by the included file. Use [`.Args N`](#args) to access the N-th
// argument, 0-indexed. Note that the contents are NOT escaped, so
// you should only include trusted template files.
//
// ```
// {{include "path/to/file.html"}}  // no arguments
// {{include "path/to/file.html" "arg0" 1 "value 2"}}  // with arguments
// ```
//
// ##### `readFile`
//
// Reads and returns the contents of another file, as-is.
// Note that the contents are NOT escaped, so you should
// only read trusted files.
//
// ```
// {{readFile "path/to/file.html"}}
// ```
//
// ##### `listFiles`
//
// Returns a list of the files in the given directory, which is relative
// to the template context's file root.
//
// ```
// {{listFiles "/mydir"}}
// ```
//
// ##### `markdown`
//
// Renders the given Markdown text as HTML and returns it. This uses the
// [Goldmark](https://github.com/yuin/goldmark) library,
// which is CommonMark compliant. It also has these extensions
// enabled: GitHub Flavored Markdown, Footnote, and syntax
// highlighting provided by [Chroma](https://github.com/alecthomas/chroma).
//
// ```
// {{markdown "My _markdown_ text"}}
// ```
//
// ##### `.RemoteIP`
//
// Returns the connection's IP address.
//
// ```
// {{.RemoteIP}}
// ```
//
// ##### `.ClientIP`
//
// Returns the real client's IP address, if `trusted_proxies` was configured,
// otherwise returns the connection's IP address.
//
// ```
// {{.ClientIP}}
// ```
//
// ##### `.Req`
//
// Accesses the current HTTP request, which has various fields, including:
//
//   - `.Method` - the method
//   - `.URL` - the URL, which in turn has component fields (Scheme, Host, Path, etc.)
//   - `.Header` - the header fields
//   - `.Host` - the Host or :authority header of the request
//
// ```
// {{.Req.Header.Get "User-Agent"}}
// ```
//
// ##### `.OriginalReq`
//
// Like [`.Req`](#req), except it accesses the original HTTP
// request before rewrites or other internal modifications.
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
// ##### `httpError`
//
// Returns an error with the given status code to the HTTP handler chain.
//
// ```
// {{if not (fileExists $includedFile)}}{{httpError 404}}{{end}}
// ```
//
// ##### `splitFrontMatter`
//
// Splits front matter out from the body. Front matter is metadata that
// appears at the very beginning of a file or string. Front matter can
// be in YAML, TOML, or JSON formats:
//
// **TOML** front matter starts and ends with `+++`:
//
// ```toml
// +++
// template = "blog"
// title = "Blog Homepage"
// sitename = "A Caddy site"
// +++
// ```
//
// **YAML** is surrounded by `---`:
//
// ```yaml
// ---
// template: blog
// title: Blog Homepage
// sitename: A Caddy site
// ---
// ```
//
// **JSON** is simply `{` and `}`:
//
// ```json
// {
// "template": "blog",
// "title": "Blog Homepage",
// "sitename": "A Caddy site"
// }
// ```
//
// The resulting front matter will be made available like so:
//
// - `.Meta` to access the metadata fields, for example: `{{$parsed.Meta.title}}`
// - `.Body` to access the body after the front matter, for example: `{{markdown $parsed.Body}}`
//
// ##### `stripHTML`
//
// Removes HTML from a string.
//
// ```
// {{stripHTML "Shows <b>only</b> text content"}}
// ```
//
// ##### `humanize`
//
// Transforms size and time inputs to a human readable format.
// This uses the [go-humanize](https://github.com/dustin/go-humanize) library.
//
// The first argument must be a format type, and the last argument
// is the input, or the input can be piped in. The supported format
// types are:
// - **size** which turns an integer amount of bytes into a string like `2.3 MB`
// - **time** which turns a time string into a relative time string like `2 weeks ago`
//
// For the `time` format, the layout for parsing the input can be configured
// by appending a colon `:` followed by the desired time layout. You can
// find the documentation on time layouts [in Go's docs](https://pkg.go.dev/time#pkg-constants).
// The default time layout is `RFC1123Z`, i.e. `Mon, 02 Jan 2006 15:04:05 -0700`.
//
// ##### `pathEscape`
//
// Passes a string through `url.PathEscape`, replacing characters that have
// special meaning in URL path parameters (`?`, `&`, `%`).
//
// Useful e.g. to include filenames containing these characters in URL path
// parameters, or use them as an `img` element's `src` attribute.
//
// ```
// {{pathEscape "50%_valid_filename?.jpg"}}
// ```
//
// ```
// {{humanize "size" "2048000"}}
// {{placeholder "http.response.header.Content-Length" | humanize "size"}}
// {{humanize "time" "Fri, 05 May 2022 15:04:05 +0200"}}
// {{humanize "time:2006-Jan-02" "2022-May-05"}}
// ```
type Templates struct {
	// The root path from which to load files. Required if template functions
	// accessing the file system are used (such as include). Default is
	// `{http.vars.root}` if set, or current working directory otherwise.
	FileRoot string `json:"file_root,omitempty"`

	// The MIME types for which to render templates. It is important to use
	// this if the route matchers do not exclude images or other binary files.
	// Default is text/plain, text/markdown, and text/html.
	MIMETypes []string `json:"mime_types,omitempty"`

	// The template action delimiters. If set, must be precisely two elements:
	// the opening and closing delimiters. Default: `["{{", "}}"]`
	Delimiters []string `json:"delimiters,omitempty"`

	// Extensions adds functions to the template's func map. These often
	// act as components on web pages, for example.
	ExtensionsRaw caddy.ModuleMap `json:"match,omitempty" caddy:"namespace=http.handlers.templates.functions"`

	customFuncs []template.FuncMap
	logger      *zap.Logger
}

// CustomFunctions is the interface for registering custom template functions.
type CustomFunctions interface {
	// CustomTemplateFunctions should return the mapping from custom function names to implementations.
	CustomTemplateFunctions() template.FuncMap
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
	t.logger = ctx.Logger()
	mods, err := ctx.LoadModule(t, "ExtensionsRaw")
	if err != nil {
		return fmt.Errorf("loading template extensions: %v", err)
	}
	for _, modIface := range mods.(map[string]any) {
		t.customFuncs = append(t.customFuncs, modIface.(CustomFunctions).CustomTemplateFunctions())
	}

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
		Root:        fs,
		Req:         r,
		RespHeader:  WrappedHeader{rr.Header()},
		config:      t,
		CustomFuncs: t.customFuncs,
	}

	err := ctx.executeTemplateInBuffer(r.URL.Path, rr.Buffer())
	if err != nil {
		// templates may return a custom HTTP error to be propagated to the client,
		// otherwise for any other error we assume the template is broken
		var handlerErr caddyhttp.HandlerError
		if errors.As(err, &handlerErr) {
			return handlerErr
		}
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
