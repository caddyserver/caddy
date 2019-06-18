package templates

import (
	"bytes"
	"fmt"
	"io"
	"net/http"
	"strconv"
	"text/template"

	"github.com/caddyserver/caddy"
	"github.com/caddyserver/caddy/modules/caddyhttp"
)

func init() {
	caddy.RegisterModule(caddy.Module{
		Name: "http.middleware.templates",
		New:  func() interface{} { return new(Templates) },
	})
}

// Templates is a middleware which execute response bodies as templates.
type Templates struct {
	FileRoot   string   `json:"file_root,omitempty"`
	Delimiters []string `json:"delimiters,omitempty"`
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

	wb := &responseBuffer{
		ResponseWriterWrapper: &caddyhttp.ResponseWriterWrapper{ResponseWriter: w},
		buf:                   buf,
	}

	err := next.ServeHTTP(wb, r)
	if err != nil {
		return err
	}

	err = t.executeTemplate(wb, r)
	if err != nil {
		return err
	}

	w.Header().Set("Content-Length", strconv.Itoa(wb.buf.Len()))
	w.Header().Del("Accept-Ranges") // we don't know ranges for dynamically-created content
	w.Header().Del("Etag")          // don't know a way to quickly generate etag for dynamic content
	w.Header().Del("Last-Modified") // useless for dynamic content since it's always changing

	w.WriteHeader(wb.statusCode)
	io.Copy(w, wb.buf)

	return nil
}

// executeTemplate executes the template contianed
// in wb.buf and replaces it with the results.
func (t *Templates) executeTemplate(wb *responseBuffer, r *http.Request) error {
	tpl := template.New(r.URL.Path)

	if len(t.Delimiters) == 2 {
		tpl.Delims(t.Delimiters[0], t.Delimiters[1])
	}

	parsedTpl, err := tpl.Parse(wb.buf.String())
	if err != nil {
		return caddyhttp.Error(http.StatusInternalServerError, err)
	}

	var fs http.FileSystem
	if t.FileRoot != "" {
		fs = http.Dir(t.FileRoot)
	}
	ctx := &templateContext{
		Root:       fs,
		Req:        r,
		RespHeader: tplWrappedHeader{wb.Header()},
	}

	wb.buf.Reset() // reuse buffer for output
	err = parsedTpl.Execute(wb.buf, ctx)
	if err != nil {
		return caddyhttp.Error(http.StatusInternalServerError, err)
	}

	return nil
}

// responseBuffer buffers the response so that it can be
// executed as a template.
type responseBuffer struct {
	*caddyhttp.ResponseWriterWrapper
	wroteHeader bool
	statusCode  int
	buf         *bytes.Buffer
}

func (rb *responseBuffer) WriteHeader(statusCode int) {
	if rb.wroteHeader {
		return
	}
	rb.statusCode = statusCode
	rb.wroteHeader = true
}

func (rb *responseBuffer) Write(data []byte) (int, error) {
	rb.WriteHeader(http.StatusOK)
	return rb.buf.Write(data)
}

// virtualResponseWriter is used in virtualized HTTP requests.
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

// Interface guards
var (
	_ caddy.Validator             = (*Templates)(nil)
	_ caddyhttp.MiddlewareHandler = (*Templates)(nil)
	_ caddyhttp.HTTPInterfaces    = (*responseBuffer)(nil)
)
