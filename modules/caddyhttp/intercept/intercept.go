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

package intercept

import (
	"bufio"
	"bytes"
	"fmt"
	"io"
	"maps"
	"net"
	"net/http"
	"slices"
	"strconv"
	"strings"
	"sync"

	"go.uber.org/zap"
	"go.uber.org/zap/zapcore"

	"github.com/caddyserver/caddy/v2"
	"github.com/caddyserver/caddy/v2/caddyconfig/caddyfile"
	"github.com/caddyserver/caddy/v2/caddyconfig/httpcaddyfile"
	"github.com/caddyserver/caddy/v2/modules/caddyhttp"
)

func init() {
	caddy.RegisterModule(Intercept{})
	httpcaddyfile.RegisterHandlerDirective("intercept", parseCaddyfile)
}

// Intercept is a middleware that intercepts then replaces or modifies the original response.
// It can, for instance, be used to implement X-Sendfile/X-Accel-Redirect-like features
// when using modules like FrankenPHP or Caddy Snake.
//
// EXPERIMENTAL: Subject to change or removal.
type Intercept struct {
	// List of handlers and their associated matchers to evaluate
	// after successful response generation.
	// The first handler that matches the original response will
	// be invoked. The original response body will not be
	// written to the client;
	// it is up to the handler to finish handling the response.
	//
	// Three new placeholders are available in this handler chain:
	// - `{http.intercept.status_code}` The status code from the response
	// - `{http.intercept.header.*}` The headers from the response
	//
	// The routes own the response once one of them writes, flushes, or
	// sets a status; a route that only sets a status sends an empty
	// body. Until then the routes see the intercepted response's headers
	// and may add, replace, or delete any field. A replacement response
	// does not inherit representation fields of the intercepted response
	// (for example Content-Length, ETag or Last-Modified) that the routes
	// left untouched; use copy_response_headers to carry such a field
	// over explicitly. A field set to exactly the intercepted value is
	// indistinguishable from an untouched one and is dropped. If no route
	// produces output, the intercepted response is sent with the routes'
	// header changes applied, and its representation fields stay the
	// intercepted ones because the intercepted body is what is sent.
	HandleResponse []caddyhttp.ResponseHandler `json:"handle_response,omitempty"`

	// Holds the named response matchers from the Caddyfile while adapting
	responseMatchers map[string]caddyhttp.ResponseMatcher

	// Holds the handle_response Caddyfile tokens while adapting
	handleResponseSegments []*caddyfile.Dispenser

	logger *zap.Logger
}

// CaddyModule returns the Caddy module information.
//
// EXPERIMENTAL: Subject to change or removal.
func (Intercept) CaddyModule() caddy.ModuleInfo {
	return caddy.ModuleInfo{
		ID:  "http.handlers.intercept",
		New: func() caddy.Module { return new(Intercept) },
	}
}

// Provision ensures that i is set up properly before use.
//
// EXPERIMENTAL: Subject to change or removal.
func (irh *Intercept) Provision(ctx caddy.Context) error {
	// set up any response routes
	for i, rh := range irh.HandleResponse {
		err := rh.Provision(ctx)
		if err != nil {
			return fmt.Errorf("provisioning response handler %d: %w", i, err)
		}
	}

	irh.logger = ctx.Logger()

	return nil
}

var bufPool = sync.Pool{
	New: func() any {
		return new(bytes.Buffer)
	},
}

// EXPERIMENTAL: Subject to change or removal.
type interceptedResponseHandler struct {
	caddyhttp.ResponseRecorder
	replacer     *caddy.Replacer
	handler      caddyhttp.ResponseHandler
	handlerIndex int
	statusCode   int
}

// EXPERIMENTAL: Subject to change or removal.
func (irh interceptedResponseHandler) Unwrap() http.ResponseWriter {
	return irh.ResponseRecorder
}

// EXPERIMENTAL: Subject to change or removal.
func (ir Intercept) ServeHTTP(w http.ResponseWriter, r *http.Request, next caddyhttp.Handler) error {
	buf := bufPool.Get().(*bytes.Buffer)
	buf.Reset()
	defer bufPool.Put(buf)

	initialHeaders := w.Header().Clone()

	repl := r.Context().Value(caddy.ReplacerCtxKey).(*caddy.Replacer)
	rec := interceptedResponseHandler{replacer: repl}
	rec.ResponseRecorder = caddyhttp.NewResponseRecorder(w, buf, func(status int, header http.Header) bool {
		// see if any response handler is configured for this original response
		for i, rh := range ir.HandleResponse {
			if rh.Match != nil && !rh.Match.Match(status, header) {
				continue
			}
			rec.handler = rh
			rec.handlerIndex = i

			// if configured to only change the status code,
			// buffer the response so we can substitute the status
			if statusCodeStr := rh.StatusCode.String(); statusCodeStr != "" {
				sc, err := strconv.Atoi(repl.ReplaceAll(statusCodeStr, ""))
				if err != nil {
					rec.statusCode = http.StatusInternalServerError
				} else {
					rec.statusCode = sc
				}

				return true
			}

			return rec.statusCode == 0
		}

		return false
	})

	if err := next.ServeHTTP(rec, r); err != nil {
		return err
	}
	if !rec.Buffered() {
		return nil
	}

	// set up the replacer so that parts of the original response can be
	// used for routing decisions
	for field, value := range rec.Header() {
		repl.Set("http.intercept.header."+field, strings.Join(value, ","))
	}
	repl.Set("http.intercept.status_code", rec.Status())

	if c := ir.logger.Check(zapcore.DebugLevel, "handling response"); c != nil {
		c.Write(zap.Int("handler", rec.handlerIndex))
	}

	// replace_status only: no routes to execute, just substitute status and write body
	if rec.handler.Routes == nil {
		if rec.statusCode == 0 {
			w.WriteHeader(rec.Status())
		} else {
			w.WriteHeader(rec.statusCode)
		}

		if buf.Len() > 0 {
			_, err := io.Copy(w, buf)

			return err
		}

		return nil
	}

	// routes own a copy of the intercepted headers; the intercepted
	// map stays untouched so the fallback can replay it
	snapshot := canonicalHeader(rec.Header().Clone())
	routeHeaders := snapshot.Clone()
	recorded := make(map[string]struct{})
	interceptStatus := rec.Status()
	if interceptStatus == 0 {
		interceptStatus = http.StatusOK
	}
	dw := &ownershipWriter{
		rw:       w,
		header:   routeHeaders,
		snapshot: snapshot,
		status:   interceptStatus,
		recorded: recorded,
	}
	copier := &interceptCopier{
		snapshot: snapshot,
		status:   interceptStatus,
		body:     buf,
		recorded: recorded,
	}
	r = r.WithContext(caddyhttp.WithResponseCopier(r.Context(), copier))

	sentinel := caddyhttp.HandlerFunc(func(sw http.ResponseWriter, req *http.Request) error {
		if dw.committed || dw.hijacked {
			return nil
		}
		dw.fallback = true
		sw.WriteHeader(dw.status)
		if buf.Len() > 0 {
			_, err := io.Copy(sw, bytes.NewReader(buf.Bytes()))
			return err
		}
		return nil
	})

	routeErr := rec.handler.Routes.Compile(sentinel).ServeHTTP(dw, r)
	if dw.hijacked {
		return routeErr
	}
	if routeErr != nil {
		if !dw.committed {
			clear(w.Header())
			maps.Copy(w.Header(), initialHeaders)
		}
		return routeErr
	}
	if dw.committed {
		return nil
	}
	dw.commitFallback(dw.status)
	if buf.Len() > 0 {
		_, err := io.Copy(w, bytes.NewReader(buf.Bytes()))
		return err
	}
	return nil
}

// representationHeaders describe the response body, so each commit path
// resolves them from whichever side owns the body it is about to send.
var representationHeaders = map[string]struct{}{
	"Content-Length":   {},
	"Content-Type":     {},
	"Content-Encoding": {},
	"Content-Range":    {},
	"Content-Language": {},
	"Content-Location": {},
	"Accept-Ranges":    {},
	"Etag":             {},
	"Last-Modified":    {},
	"Digest":           {},
}

// canonicalHeader folds keys to their canonical form so a lookup does not
// depend on how the recorder happened to store the field.
func canonicalHeader(header http.Header) http.Header {
	canonical := make(http.Header, len(header))
	for k, vv := range header {
		ck := http.CanonicalHeaderKey(k)
		canonical[ck] = append(canonical[ck], vv...)
	}
	return canonical
}

func equalHeaderValues(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

// ownershipWriter holds the route's commit back until it produces output.
type ownershipWriter struct {
	rw        http.ResponseWriter
	header    http.Header
	snapshot  http.Header
	status    int
	recorded  map[string]struct{}
	committed bool
	fallback  bool
	hijacked  bool
}

func (dw *ownershipWriter) Header() http.Header {
	if dw.committed || dw.hijacked {
		return dw.rw.Header()
	}
	return dw.header
}

func (dw *ownershipWriter) WriteHeader(status int) {
	if dw.hijacked || dw.committed {
		return
	}
	if status >= 100 && status <= 199 {
		if status == http.StatusSwitchingProtocols {
			if dw.fallback {
				dw.commitFallback(status)
			} else {
				dw.commitReplacement(status)
			}
			return
		}
		// informational responses carry the route's headers, not the
		// intercepted response's
		dw.installRouteHeaders()
		dw.rw.WriteHeader(status)
		return
	}
	if dw.fallback {
		dw.commitFallback(status)
		return
	}
	dw.commitReplacement(status)
}

func (dw *ownershipWriter) Write(p []byte) (int, error) {
	if dw.hijacked {
		return 0, http.ErrHijacked
	}
	if !dw.committed {
		if dw.fallback {
			dw.commitFallback(dw.status)
		} else {
			dw.commitReplacement(http.StatusOK)
		}
	}
	return dw.rw.Write(p)
}

// Flush commits on first output, then flushes the real writer.
func (dw *ownershipWriter) Flush() {
	if dw.hijacked {
		return
	}
	if !dw.committed {
		if dw.fallback {
			dw.commitFallback(dw.status)
		} else {
			dw.commitReplacement(http.StatusOK)
		}
	}
	//nolint:bodyclose
	http.NewResponseController(dw.rw).Flush()
}

// FlushError commits on first output, then flushes the real writer.
func (dw *ownershipWriter) FlushError() error {
	if dw.hijacked {
		return http.ErrHijacked
	}
	if !dw.committed {
		if dw.fallback {
			dw.commitFallback(dw.status)
		} else {
			dw.commitReplacement(http.StatusOK)
		}
	}
	//nolint:bodyclose
	return http.NewResponseController(dw.rw).Flush()
}

func (dw *ownershipWriter) ReadFrom(r io.Reader) (int64, error) {
	if dw.hijacked {
		return 0, http.ErrHijacked
	}
	if !dw.committed {
		if dw.fallback {
			dw.commitFallback(dw.status)
		} else {
			dw.commitReplacement(http.StatusOK)
		}
	}
	if rf, ok := dw.rw.(io.ReaderFrom); ok {
		return rf.ReadFrom(r)
	}
	return io.Copy(dw.rw, r)
}

// Push never commits the response.
func (dw *ownershipWriter) Push(target string, opts *http.PushOptions) error {
	if pusher, ok := dw.rw.(http.Pusher); ok {
		return pusher.Push(target, opts)
	}
	return caddyhttp.ErrNotImplemented
}

func (dw *ownershipWriter) Hijack() (net.Conn, *bufio.ReadWriter, error) {
	if dw.hijacked {
		return nil, nil, http.ErrHijacked
	}
	//nolint:bodyclose
	conn, brw, err := http.NewResponseController(dw.rw).Hijack()
	if err != nil {
		return nil, nil, err
	}
	// the flag also stops a later Flush from touching the hijacked writer
	dw.hijacked = true
	return conn, brw, nil
}

// Unwrap returns the real writer so ResponseController reaches it.
func (dw *ownershipWriter) Unwrap() http.ResponseWriter {
	return dw.rw
}

// commitReplacement sends the route's body, so the route owns the
// representation fields unless it left them exactly as intercepted.
func (dw *ownershipWriter) commitReplacement(status int) {
	if dw.committed || dw.hijacked {
		return
	}
	filtered := make(http.Header, len(dw.header))
	for k, vv := range dw.header {
		ck := http.CanonicalHeaderKey(k)
		if _, ok := representationHeaders[ck]; ok {
			_, wasRecorded := dw.recorded[ck]
			// an empty value is a deliberate marker (no-sniff), not inherited metadata
			if !wasRecorded && len(vv) > 0 && equalHeaderValues(vv, dw.snapshot[ck]) {
				continue
			}
		}
		filtered[k] = append([]string(nil), vv...)
	}
	dw.installHeaders(filtered)
	dw.rw.WriteHeader(status)
	dw.committed = true
}

// commitFallback sends the intercepted body, so a representation field
// the route changed or added takes the intercepted value. A deletion
// still stands, but an empty value is not a no-sniff marker here.
func (dw *ownershipWriter) commitFallback(status int) {
	if dw.committed || dw.hijacked {
		return
	}
	header := make(http.Header, len(dw.header))
	for k, vv := range dw.header {
		ck := http.CanonicalHeaderKey(k)
		if _, ok := representationHeaders[ck]; ok {
			snap, ok := dw.snapshot[ck]
			if !ok {
				continue
			}
			header[ck] = append([]string(nil), snap...)
			continue
		}
		header[k] = append([]string(nil), vv...)
	}
	dw.installHeaders(header)
	dw.rw.WriteHeader(status)
	dw.committed = true
}

func (dw *ownershipWriter) installRouteHeaders() {
	dw.installHeaders(dw.header)
}

func (dw *ownershipWriter) installHeaders(header http.Header) {
	clear(dw.rw.Header())
	for k, vv := range header {
		dw.rw.Header()[k] = append([]string(nil), vv...)
	}
}

// interceptCopier replays the intercepted response for copy handlers.
type interceptCopier struct {
	snapshot http.Header
	status   int
	body     *bytes.Buffer
	recorded map[string]struct{}
}

func (c *interceptCopier) CopyResponseHeaders(w http.ResponseWriter, include, exclude map[string]struct{}) {
	for field, values := range c.snapshot {
		if len(include) > 0 {
			if _, ok := include[field]; !ok {
				continue
			}
		}
		if len(exclude) > 0 {
			if _, ok := exclude[field]; ok {
				continue
			}
		}
		// the route map starts as a clone, so only add missing values
		existing := w.Header()[field]
		for _, value := range values {
			if !slices.Contains(existing, value) {
				w.Header().Add(field, value)
			}
		}
		// framing follows the new body, so Content-Length is never kept
		if ck := http.CanonicalHeaderKey(field); ck != "Content-Length" {
			if _, ok := representationHeaders[ck]; ok {
				c.recorded[ck] = struct{}{}
			}
		}
	}
}

func (c *interceptCopier) CopyResponse(w http.ResponseWriter, r *http.Request, statusCode int) error {
	// the bytes are the intercepted body, so the intercepted
	// representation fields still describe them
	for field := range c.snapshot {
		if ck := http.CanonicalHeaderKey(field); ck != "Content-Length" {
			if _, ok := representationHeaders[ck]; ok {
				c.recorded[ck] = struct{}{}
			}
		}
	}
	status := statusCode
	if status == 0 {
		status = c.status
	}
	if status == 0 {
		status = http.StatusOK
	}
	w.WriteHeader(status)
	if c.body.Len() > 0 {
		_, err := io.Copy(w, bytes.NewReader(c.body.Bytes()))
		return err
	}
	return nil
}

// UnmarshalCaddyfile sets up the handler from Caddyfile tokens. Syntax:
//
//	intercept [<matcher>] {
//	    # intercept original responses
//	    @name {
//	        status <code...>
//	        header <field> [<value>]
//	    }
//	    replace_status [<matcher>] <status_code>
//	    handle_response [<matcher>] {
//	        <directives...>
//	    }
//	}
//
// The FinalizeUnmarshalCaddyfile method should be called after this
// to finalize parsing of "handle_response" blocks, if possible.
//
// EXPERIMENTAL: Subject to change or removal.
func (i *Intercept) UnmarshalCaddyfile(d *caddyfile.Dispenser) error {
	// collect the response matchers defined as subdirectives
	// prefixed with "@" for use with "handle_response" blocks
	i.responseMatchers = make(map[string]caddyhttp.ResponseMatcher)

	d.Next() // consume the directive name
	for d.NextBlock(0) {
		// if the subdirective has an "@" prefix then we
		// parse it as a response matcher for use with "handle_response"
		if strings.HasPrefix(d.Val(), matcherPrefix) {
			err := caddyhttp.ParseNamedResponseMatcher(d.NewFromNextSegment(), i.responseMatchers)
			if err != nil {
				return err
			}
			continue
		}

		switch d.Val() {
		case "handle_response":
			// delegate the parsing of handle_response to the caller,
			// since we need the httpcaddyfile.Helper to parse subroutes.
			// See h.FinalizeUnmarshalCaddyfile
			i.handleResponseSegments = append(i.handleResponseSegments, d.NewFromNextSegment())

		case "replace_status":
			args := d.RemainingArgs()
			if len(args) != 1 && len(args) != 2 {
				return d.Errf("must have one or two arguments: an optional response matcher, and a status code")
			}

			responseHandler := caddyhttp.ResponseHandler{}

			if len(args) == 2 {
				if !strings.HasPrefix(args[0], matcherPrefix) {
					return d.Errf("must use a named response matcher, starting with '@'")
				}
				foundMatcher, ok := i.responseMatchers[args[0]]
				if !ok {
					return d.Errf("no named response matcher defined with name '%s'", args[0][1:])
				}
				responseHandler.Match = &foundMatcher
				responseHandler.StatusCode = caddyhttp.WeakString(args[1])
			} else if len(args) == 1 {
				responseHandler.StatusCode = caddyhttp.WeakString(args[0])
			}

			// make sure there's no block, cause it doesn't make sense
			if nesting := d.Nesting(); d.NextBlock(nesting) {
				return d.Errf("cannot define routes for 'replace_status', use 'handle_response' instead.")
			}

			i.HandleResponse = append(
				i.HandleResponse,
				responseHandler,
			)

		default:
			return d.Errf("unrecognized subdirective %s", d.Val())
		}
	}

	return nil
}

// FinalizeUnmarshalCaddyfile finalizes the Caddyfile parsing which
// requires having an httpcaddyfile.Helper to function, to parse subroutes.
//
// EXPERIMENTAL: Subject to change or removal.
func (i *Intercept) FinalizeUnmarshalCaddyfile(helper httpcaddyfile.Helper) error {
	for _, d := range i.handleResponseSegments {
		// consume the "handle_response" token
		d.Next()
		args := d.RemainingArgs()

		if len(args) > 1 {
			return d.Errf("too many arguments for 'handle_response': only a single response matcher name is allowed, but got: %s", args)
		}

		var matcher *caddyhttp.ResponseMatcher
		if len(args) == 1 {
			// the first arg should always be a matcher.
			if !strings.HasPrefix(args[0], matcherPrefix) {
				return d.Errf("must use a named response matcher, starting with '@'")
			}

			foundMatcher, ok := i.responseMatchers[args[0]]
			if !ok {
				return d.Errf("no named response matcher defined with name '%s'", args[0][1:])
			}
			matcher = &foundMatcher
		}

		// parse the block as routes
		handler, err := httpcaddyfile.ParseSegmentAsSubroute(helper.WithDispenser(d.NewFromNextSegment()))
		if err != nil {
			return err
		}
		subroute, ok := handler.(*caddyhttp.Subroute)
		if !ok {
			return helper.Errf("segment was not parsed as a subroute")
		}
		i.HandleResponse = append(
			i.HandleResponse,
			caddyhttp.ResponseHandler{
				Match:  matcher,
				Routes: subroute.Routes,
			},
		)
	}

	// move the handle_response entries without a matcher to the end.
	// we can't use sort.SliceStable because it will reorder the rest of the
	// entries which may be undesirable because we don't have a good
	// heuristic to use for sorting.
	withoutMatchers := []caddyhttp.ResponseHandler{}
	withMatchers := []caddyhttp.ResponseHandler{}
	for _, hr := range i.HandleResponse {
		if hr.Match == nil {
			withoutMatchers = append(withoutMatchers, hr)
		} else {
			withMatchers = append(withMatchers, hr)
		}
	}
	i.HandleResponse = append(withMatchers, withoutMatchers...)

	// clean up the bits we only needed for adapting
	i.handleResponseSegments = nil
	i.responseMatchers = nil

	return nil
}

const matcherPrefix = "@"

func parseCaddyfile(helper httpcaddyfile.Helper) (caddyhttp.MiddlewareHandler, error) {
	var ir Intercept
	if err := ir.UnmarshalCaddyfile(helper.Dispenser); err != nil {
		return nil, err
	}

	if err := ir.FinalizeUnmarshalCaddyfile(helper); err != nil {
		return nil, err
	}

	return ir, nil
}

// Interface guards
var (
	_ caddy.Provisioner           = (*Intercept)(nil)
	_ caddyfile.Unmarshaler       = (*Intercept)(nil)
	_ caddyhttp.MiddlewareHandler = (*Intercept)(nil)
	_ caddyhttp.ResponseCopier    = (*interceptCopier)(nil)
	_ http.ResponseWriter         = (*ownershipWriter)(nil)
	_ http.Flusher                = (*ownershipWriter)(nil)
	_ http.Hijacker               = (*ownershipWriter)(nil)
	_ http.Pusher                 = (*ownershipWriter)(nil)
	_ io.ReaderFrom               = (*ownershipWriter)(nil)
)
