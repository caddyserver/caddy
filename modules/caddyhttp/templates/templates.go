package templates

import (
	"bytes"
	"fmt"
	"io"
	"net/http"
	"strconv"
	"strings"

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

	shouldBuf := func(status int) bool {
		return strings.HasPrefix(w.Header().Get("Content-Type"), "text/")
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
	w.Header().Del("Etag")          // don't know a way to quickly generate etag for dynamic content
	w.Header().Del("Last-Modified") // useless for dynamic content since it's always changing

	w.WriteHeader(rec.Status())
	io.Copy(w, buf)

	return nil
}

// executeTemplate executes the template contained in wb.buf and replaces it with the results.
func (t *Templates) executeTemplate(rr caddyhttp.ResponseRecorder, r *http.Request) error {
	var fs http.FileSystem
	if t.FileRoot != "" {
		fs = http.Dir(t.FileRoot)
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

// Interface guards
var (
	_ caddy.Validator             = (*Templates)(nil)
	_ caddyhttp.MiddlewareHandler = (*Templates)(nil)
)
