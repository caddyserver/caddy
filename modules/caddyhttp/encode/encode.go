// Package encode implements an encoder middleware for Caddy. The initial
// enhancements related to Accept-Encoding, minimum content length, and
// buffer/writer pools were adapted from https://github.com/xi2/httpgzip
// then modified heavily to accommodate modular encoders. Code borrowed
// from that repository is Copyright (c) 2015 The Httpgzip Authors.
package encode

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"sort"
	"strconv"
	"strings"
	"sync"

	"github.com/caddyserver/caddy2"
	"github.com/caddyserver/caddy2/modules/caddyhttp"
)

func init() {
	caddy2.RegisterModule(caddy2.Module{
		Name: "http.middleware.encode",
		New:  func() interface{} { return new(Encode) },
	})
}

// Encode is a middleware which can encode responses.
type Encode struct {
	EncodingsRaw map[string]json.RawMessage `json:"encodings,omitempty"`
	Prefer       []string                   `json:"prefer,omitempty"`
	MinLength    int                        `json:"minimum_length,omitempty"`

	Encodings map[string]Encoding `json:"-"`

	writerPools map[string]*sync.Pool // TODO: these pools do not get reused through config reloads...
}

// Provision provisions enc.
func (enc *Encode) Provision(ctx caddy2.Context) error {
	enc.Encodings = make(map[string]Encoding)
	enc.writerPools = make(map[string]*sync.Pool)

	for modName, rawMsg := range enc.EncodingsRaw {
		val, err := ctx.LoadModule("http.encoders."+modName, rawMsg)
		if err != nil {
			return fmt.Errorf("loading encoder module '%s': %v", modName, err)
		}
		encoder := val.(Encoding)
		enc.Encodings[modName] = encoder

		enc.writerPools[modName] = &sync.Pool{
			New: func() interface{} {
				return encoder.NewEncoder()
			},
		}
	}
	enc.EncodingsRaw = nil // allow GC to deallocate - TODO: Does this help?

	if enc.MinLength == 0 {
		enc.MinLength = defaultMinLength
	}

	return nil
}

func (enc *Encode) ServeHTTP(w http.ResponseWriter, r *http.Request, next caddyhttp.Handler) error {
	for _, encName := range acceptedEncodings(r) {
		if _, ok := enc.writerPools[encName]; !ok {
			continue // encoding not offered
		}
		w = enc.openResponseWriter(encName, w)
		defer w.(*responseWriter).Close()
		break
	}

	return next.ServeHTTP(w, r)
}

// openResponseWriter creates a new response writer that may (or may not)
// encode the response with encodingName. The returned response writer MUST
// be closed after the handler completes.
func (enc *Encode) openResponseWriter(encodingName string, w http.ResponseWriter) *responseWriter {
	buf := bufPool.Get().(*bytes.Buffer)
	buf.Reset()
	return &responseWriter{
		ResponseWriterWrapper: &caddyhttp.ResponseWriterWrapper{ResponseWriter: w},
		encodingName:          encodingName,
		buf:                   buf,
		config:                enc,
	}
}

// responseWriter writes to an underlying response writer
// using the encoding represented by encodingName and
// configured by config.
type responseWriter struct {
	*caddyhttp.ResponseWriterWrapper
	encodingName string
	w            Encoder
	buf          *bytes.Buffer
	config       *Encode
	statusCode   int
}

// WriteHeader stores the status to write when the time comes
// to actually write the header.
func (rw *responseWriter) WriteHeader(status int) {
	rw.statusCode = status
}

// Write writes to the response. If the response qualifies,
// it is encoded using the encoder, which is initialized
// if not done so already.
func (rw *responseWriter) Write(p []byte) (int, error) {
	var n, written int
	var err error

	if rw.buf != nil && rw.config.MinLength > 0 {
		written = rw.buf.Len()
		_, err := rw.buf.Write(p)
		if err != nil {
			return 0, err
		}
		if rw.buf.Len() < rw.config.MinLength {
			return len(p), nil
		}
		rw.init()
		p = rw.buf.Bytes()
		defer func() {
			bufPool.Put(rw.buf)
			rw.buf = nil
		}()
	}

	switch {
	case rw.w != nil:
		n, err = rw.w.Write(p)
	default:
		n, err = rw.ResponseWriter.Write(p)
	}
	n -= written
	if n < 0 {
		n = 0
	}
	return n, err
}

// init should be called once we know we are writing an encoded response.
func (rw *responseWriter) init() {
	if rw.Header().Get("Content-Encoding") == "" && rw.buf.Len() >= rw.config.MinLength {
		rw.w = rw.config.writerPools[rw.encodingName].Get().(Encoder)
		rw.w.Reset(rw.ResponseWriter)
		rw.Header().Del("Content-Length") // https://github.com/golang/go/issues/14975
		rw.Header().Set("Content-Encoding", rw.encodingName)
	}
	rw.Header().Del("Accept-Ranges") // we don't know ranges for dynamically-encoded content
	rw.ResponseWriter.WriteHeader(rw.statusCode)
}

// Close writes any remaining buffered response and
// deallocates any active resources.
func (rw *responseWriter) Close() error {
	var err error
	if rw.buf != nil {
		rw.init()
		p := rw.buf.Bytes()
		defer func() {
			bufPool.Put(rw.buf)
			rw.buf = nil
		}()
		switch {
		case rw.w != nil:
			_, err = rw.w.Write(p)
		default:
			_, err = rw.ResponseWriter.Write(p)
		}
	}
	if rw.w != nil {
		err2 := rw.w.Close()
		if err2 != nil && err == nil {
			err = err2
		}
		rw.config.writerPools[rw.encodingName].Put(rw.w)
		rw.w = nil
	}
	return err
}

// acceptedEncodings returns the list of encodings that the
// client supports, in descending order of preference. If
// the Sec-WebSocket-Key header is present then non-identity
// encodings are not considered. See
// http://www.w3.org/Protocols/rfc2616/rfc2616-sec14.html.
func acceptedEncodings(r *http.Request) []string {
	acceptEncHeader := r.Header.Get("Accept-Encoding")
	websocketKey := r.Header.Get("Sec-WebSocket-Key")
	if acceptEncHeader == "" {
		return []string{}
	}

	var prefs []encodingPreference

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
		// use a small theshold to account for float precision
		if qFactor < 0.00001 {
			continue
		}

		// don't encode WebSocket handshakes
		if websocketKey != "" && encName != "identity" {
			continue
		}

		prefs = append(prefs, encodingPreference{
			encoding: encName,
			q:        qFactor,
		})
	}

	// sort preferences by descending q-factor
	sort.Slice(prefs, func(i, j int) bool { return prefs[i].q > prefs[j].q })

	// TODO: If no preference, or same pref for all encodings,
	// and not websocket, use default encoding ordering (enc.Prefer)
	// for those which are accepted by the client

	prefEncNames := make([]string, len(prefs))
	for i := range prefs {
		prefEncNames[i] = prefs[i].encoding
	}

	return prefEncNames
}

// encodingPreference pairs an encoding with its q-factor.
type encodingPreference struct {
	encoding string
	q        float64
}

// Encoder is a type which can encode a stream of data.
type Encoder interface {
	io.WriteCloser
	Reset(io.Writer)
}

// Encoding is a type which can create encoders of its kind.
type Encoding interface {
	NewEncoder() Encoder
}

var bufPool = sync.Pool{
	New: func() interface{} {
		return new(bytes.Buffer)
	},
}

// defaultMinLength is the minimum length at which to compress content.
const defaultMinLength = 512

// Interface guards
var (
	_ caddy2.Provisioner          = (*Encode)(nil)
	_ caddyhttp.MiddlewareHandler = (*Encode)(nil)
	_ caddyhttp.HTTPInterfaces    = (*responseWriter)(nil)
)
