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

// Package encode implements an encoder middleware for Caddy. The initial
// enhancements related to Accept-Encoding, minimum content length, and
// buffer/writer pools were adapted from https://github.com/xi2/httpgzip
// then modified heavily to accommodate modular encoders and fix bugs.
// Code borrowed from that repository is Copyright (c) 2015 The Httpgzip Authors.
package encode

import (
	"fmt"
	"io"
	"math"
	"net/http"
	"sort"
	"strconv"
	"strings"
	"sync"

	"github.com/caddyserver/caddy/v2"
	"github.com/caddyserver/caddy/v2/modules/caddyhttp"
)

func init() {
	caddy.RegisterModule(Encode{})
}

// Encode is a middleware which can encode responses.
type Encode struct {
	// Selection of compression algorithms to choose from. The best one
	// will be chosen based on the client's Accept-Encoding header.
	EncodingsRaw caddy.ModuleMap `json:"encodings,omitempty" caddy:"namespace=http.encoders"`

	// If the client has no strong preference, choose these encodings in order.
	Prefer []string `json:"prefer,omitempty"`

	// Only encode responses that are at least this many bytes long.
	MinLength int `json:"minimum_length,omitempty"`

	// Only encode responses that match against this ResponseMmatcher.
	// The default is a collection of text-based Content-Type headers.
	Matcher *caddyhttp.ResponseMatcher `json:"match,omitempty"`

	writerPools map[string]*sync.Pool // TODO: these pools do not get reused through config reloads...
}

// CaddyModule returns the Caddy module information.
func (Encode) CaddyModule() caddy.ModuleInfo {
	return caddy.ModuleInfo{
		ID:  "http.handlers.encode",
		New: func() caddy.Module { return new(Encode) },
	}
}

// Provision provisions enc.
func (enc *Encode) Provision(ctx caddy.Context) error {
	mods, err := ctx.LoadModule(enc, "EncodingsRaw")
	if err != nil {
		return fmt.Errorf("loading encoder modules: %v", err)
	}
	for modName, modIface := range mods.(map[string]any) {
		err = enc.addEncoding(modIface.(Encoding))
		if err != nil {
			return fmt.Errorf("adding encoding %s: %v", modName, err)
		}
	}
	if enc.MinLength == 0 {
		enc.MinLength = defaultMinLength
	}

	if enc.Matcher == nil {
		// common text-based content types
		enc.Matcher = &caddyhttp.ResponseMatcher{
			Headers: http.Header{
				"Content-Type": []string{
					"text/*",
					"application/json*",
					"application/javascript*",
					"application/xhtml+xml*",
					"application/atom+xml*",
					"application/rss+xml*",
					"image/svg+xml*",
				},
			},
		}
	}

	return nil
}

// Validate ensures that enc's configuration is valid.
func (enc *Encode) Validate() error {
	check := make(map[string]bool)
	for _, encName := range enc.Prefer {
		if _, ok := enc.writerPools[encName]; !ok {
			return fmt.Errorf("encoding %s not enabled", encName)
		}

		if _, ok := check[encName]; ok {
			return fmt.Errorf("encoding %s is duplicated in prefer", encName)
		}
		check[encName] = true
	}

	return nil
}

func isEncodeAllowed(h http.Header) bool {
	return !strings.Contains(h.Get("Cache-Control"), "no-transform")
}

func (enc *Encode) ServeHTTP(w http.ResponseWriter, r *http.Request, next caddyhttp.Handler) error {
	if isEncodeAllowed(r.Header) {
		for _, encName := range AcceptedEncodings(r, enc.Prefer) {
			if _, ok := enc.writerPools[encName]; !ok {
				continue // encoding not offered
			}
			w = enc.openResponseWriter(encName, w)
			defer w.(*responseWriter).Close()
			break
		}
	}
	return next.ServeHTTP(w, r)
}

func (enc *Encode) addEncoding(e Encoding) error {
	ae := e.AcceptEncoding()
	if ae == "" {
		return fmt.Errorf("encoder does not specify an Accept-Encoding value")
	}
	if _, ok := enc.writerPools[ae]; ok {
		return fmt.Errorf("encoder already added: %s", ae)
	}
	if enc.writerPools == nil {
		enc.writerPools = make(map[string]*sync.Pool)
	}
	enc.writerPools[ae] = &sync.Pool{
		New: func() any {
			return e.NewEncoder()
		},
	}
	return nil
}

// openResponseWriter creates a new response writer that may (or may not)
// encode the response with encodingName. The returned response writer MUST
// be closed after the handler completes.
func (enc *Encode) openResponseWriter(encodingName string, w http.ResponseWriter) *responseWriter {
	var rw responseWriter
	return enc.initResponseWriter(&rw, encodingName, w)
}

// initResponseWriter initializes the responseWriter instance
// allocated in openResponseWriter, enabling mid-stack inlining.
func (enc *Encode) initResponseWriter(rw *responseWriter, encodingName string, wrappedRW http.ResponseWriter) *responseWriter {
	if httpInterfaces, ok := wrappedRW.(caddyhttp.HTTPInterfaces); ok {
		rw.HTTPInterfaces = httpInterfaces
	} else {
		rw.HTTPInterfaces = &caddyhttp.ResponseWriterWrapper{ResponseWriter: wrappedRW}
	}
	rw.encodingName = encodingName
	rw.config = enc

	return rw
}

// responseWriter writes to an underlying response writer
// using the encoding represented by encodingName and
// configured by config.
type responseWriter struct {
	caddyhttp.HTTPInterfaces
	encodingName string
	w            Encoder
	config       *Encode
	statusCode   int
	wroteHeader  bool
}

// WriteHeader stores the status to write when the time comes
// to actually write the header.
func (rw *responseWriter) WriteHeader(status int) {
	rw.statusCode = status
}

// Match determines, if encoding should be done based on the ResponseMatcher.
func (enc *Encode) Match(rw *responseWriter) bool {
	return enc.Matcher.Match(rw.statusCode, rw.Header())
}

// Flush implements http.Flusher. It delays the actual Flush of the underlying ResponseWriterWrapper
// until headers were written.
func (rw *responseWriter) Flush() {
	if !rw.wroteHeader {
		// flushing the underlying ResponseWriter will write header and status code,
		// but we need to delay that until we can determine if we must encode and
		// therefore add the Content-Encoding header; this happens in the first call
		// to rw.Write (see bug in #4314)
		return
	}
	rw.HTTPInterfaces.Flush()
}

// Write writes to the response. If the response qualifies,
// it is encoded using the encoder, which is initialized
// if not done so already.
func (rw *responseWriter) Write(p []byte) (int, error) {
	// ignore zero data writes, probably head request
	if len(p) == 0 {
		return 0, nil
	}

	// sniff content-type and determine content-length
	if !rw.wroteHeader && rw.config.MinLength > 0 {
		var gtMinLength bool
		if len(p) > rw.config.MinLength {
			gtMinLength = true
		} else if cl, err := strconv.Atoi(rw.Header().Get("Content-Length")); err == nil && cl > rw.config.MinLength {
			gtMinLength = true
		}

		if gtMinLength {
			if rw.Header().Get("Content-Type") == "" {
				rw.Header().Set("Content-Type", http.DetectContentType(p))
			}
			rw.init()
		}
	}

	// before we write to the response, we need to make
	// sure the header is written exactly once; we do
	// that by checking if a status code has been set,
	// and if so, that means we haven't written the
	// header OR the default status code will be written
	// by the standard library
	if !rw.wroteHeader {
		if rw.statusCode != 0 {
			rw.HTTPInterfaces.WriteHeader(rw.statusCode)
		}
		rw.wroteHeader = true
	}

	if rw.w != nil {
		return rw.w.Write(p)
	} else {
		return rw.HTTPInterfaces.Write(p)
	}
}

// Close writes any remaining buffered response and
// deallocates any active resources.
func (rw *responseWriter) Close() error {
	// didn't write, probably head request
	if !rw.wroteHeader {
		cl, err := strconv.Atoi(rw.Header().Get("Content-Length"))
		if err == nil && cl > rw.config.MinLength {
			rw.init()
		}

		// issue #5059, don't write status code if not set explicitly.
		if rw.statusCode != 0 {
			rw.HTTPInterfaces.WriteHeader(rw.statusCode)
		}
		rw.wroteHeader = true
	}

	var err error
	if rw.w != nil {
		err = rw.w.Close()
		rw.w.Reset(nil)
		rw.config.writerPools[rw.encodingName].Put(rw.w)
		rw.w = nil
	}
	return err
}

// init should be called before we write a response, if rw.buf has contents.
func (rw *responseWriter) init() {
	if rw.Header().Get("Content-Encoding") == "" && isEncodeAllowed(rw.Header()) &&
		rw.config.Match(rw) {

		rw.w = rw.config.writerPools[rw.encodingName].Get().(Encoder)
		rw.w.Reset(rw.HTTPInterfaces)
		rw.Header().Del("Content-Length") // https://github.com/golang/go/issues/14975
		rw.Header().Set("Content-Encoding", rw.encodingName)
		rw.Header().Add("Vary", "Accept-Encoding")
		rw.Header().Del("Accept-Ranges") // we don't know ranges for dynamically-encoded content
	}
}

// AcceptedEncodings returns the list of encodings that the
// client supports, in descending order of preference.
// The client preference via q-factor and the server
// preference via Prefer setting are taken into account. If
// the Sec-WebSocket-Key header is present then non-identity
// encodings are not considered. See
// http://www.w3.org/Protocols/rfc2616/rfc2616-sec14.html.
func AcceptedEncodings(r *http.Request, preferredOrder []string) []string {
	acceptEncHeader := r.Header.Get("Accept-Encoding")
	websocketKey := r.Header.Get("Sec-WebSocket-Key")
	if acceptEncHeader == "" {
		return []string{}
	}

	prefs := []encodingPreference{}

	for _, accepted := range strings.Split(acceptEncHeader, ",") {
		parts := strings.Split(accepted, ";")
		encName := strings.ToLower(strings.TrimSpace(parts[0]))

		// determine q-factor
		qFactor := 1.0
		if len(parts) > 1 {
			qFactorStr := strings.ToLower(strings.TrimSpace(parts[1]))
			if strings.HasPrefix(qFactorStr, "q=") {
				if qFactorFloat, err := strconv.ParseFloat(qFactorStr[2:], 32); err == nil {
					if qFactorFloat >= 0 && qFactorFloat <= 1 {
						qFactor = qFactorFloat
					}
				}
			}
		}

		// encodings with q-factor of 0 are not accepted;
		// use a small threshold to account for float precision
		if qFactor < 0.00001 {
			continue
		}

		// don't encode WebSocket handshakes
		if websocketKey != "" && encName != "identity" {
			continue
		}

		// set server preference
		prefOrder := -1
		for i, p := range preferredOrder {
			if encName == p {
				prefOrder = len(preferredOrder) - i
				break
			}
		}

		prefs = append(prefs, encodingPreference{
			encoding:    encName,
			q:           qFactor,
			preferOrder: prefOrder,
		})
	}

	// sort preferences by descending q-factor first, then by preferOrder
	sort.Slice(prefs, func(i, j int) bool {
		if math.Abs(prefs[i].q-prefs[j].q) < 0.00001 {
			return prefs[i].preferOrder > prefs[j].preferOrder
		}
		return prefs[i].q > prefs[j].q
	})

	prefEncNames := make([]string, len(prefs))
	for i := range prefs {
		prefEncNames[i] = prefs[i].encoding
	}

	return prefEncNames
}

// encodingPreference pairs an encoding with its q-factor.
type encodingPreference struct {
	encoding    string
	q           float64
	preferOrder int
}

// Encoder is a type which can encode a stream of data.
type Encoder interface {
	io.WriteCloser
	Reset(io.Writer)
}

// Encoding is a type which can create encoders of its kind
// and return the name used in the Accept-Encoding header.
type Encoding interface {
	AcceptEncoding() string
	NewEncoder() Encoder
}

// Precompressed is a type which returns filename suffix of precompressed
// file and Accept-Encoding header to use when serving this file.
type Precompressed interface {
	AcceptEncoding() string
	Suffix() string
}

// defaultMinLength is the minimum length at which to compress content.
const defaultMinLength = 512

// Interface guards
var (
	_ caddy.Provisioner           = (*Encode)(nil)
	_ caddy.Validator             = (*Encode)(nil)
	_ caddyhttp.MiddlewareHandler = (*Encode)(nil)
	_ caddyhttp.HTTPInterfaces    = (*responseWriter)(nil)
)
