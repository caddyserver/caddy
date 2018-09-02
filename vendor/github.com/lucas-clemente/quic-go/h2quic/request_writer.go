package h2quic

import (
	"bytes"
	"fmt"
	"net/http"
	"strconv"
	"strings"
	"sync"

	"golang.org/x/net/http/httpguts"
	"golang.org/x/net/http2"
	"golang.org/x/net/http2/hpack"

	quic "github.com/lucas-clemente/quic-go"
	"github.com/lucas-clemente/quic-go/internal/protocol"
	"github.com/lucas-clemente/quic-go/internal/utils"
)

type requestWriter struct {
	mutex        sync.Mutex
	headerStream quic.Stream

	henc *hpack.Encoder
	hbuf bytes.Buffer // HPACK encoder writes into this

	logger utils.Logger
}

const defaultUserAgent = "quic-go"

func newRequestWriter(headerStream quic.Stream, logger utils.Logger) *requestWriter {
	rw := &requestWriter{
		headerStream: headerStream,
		logger:       logger,
	}
	rw.henc = hpack.NewEncoder(&rw.hbuf)
	return rw
}

func (w *requestWriter) WriteRequest(req *http.Request, dataStreamID protocol.StreamID, endStream, requestGzip bool) error {
	// TODO: add support for trailers
	// TODO: add support for gzip compression
	// TODO: write continuation frames, if the header frame is too long

	w.mutex.Lock()
	defer w.mutex.Unlock()

	w.encodeHeaders(req, requestGzip, "", actualContentLength(req))
	h2framer := http2.NewFramer(w.headerStream, nil)
	return h2framer.WriteHeaders(http2.HeadersFrameParam{
		StreamID:      uint32(dataStreamID),
		EndHeaders:    true,
		EndStream:     endStream,
		BlockFragment: w.hbuf.Bytes(),
		Priority:      http2.PriorityParam{Weight: 0xff},
	})
}

// the rest of this files is copied from http2.Transport
func (w *requestWriter) encodeHeaders(req *http.Request, addGzipHeader bool, trailers string, contentLength int64) ([]byte, error) {
	w.hbuf.Reset()

	host := req.Host
	if host == "" {
		host = req.URL.Host
	}
	host, err := httpguts.PunycodeHostPort(host)
	if err != nil {
		return nil, err
	}

	var path string
	if req.Method != "CONNECT" {
		path = req.URL.RequestURI()
		if !validPseudoPath(path) {
			orig := path
			path = strings.TrimPrefix(path, req.URL.Scheme+"://"+host)
			if !validPseudoPath(path) {
				if req.URL.Opaque != "" {
					return nil, fmt.Errorf("invalid request :path %q from URL.Opaque = %q", orig, req.URL.Opaque)
				}
				return nil, fmt.Errorf("invalid request :path %q", orig)
			}
		}
	}

	// Check for any invalid headers and return an error before we
	// potentially pollute our hpack state. (We want to be able to
	// continue to reuse the hpack encoder for future requests)
	for k, vv := range req.Header {
		if !httpguts.ValidHeaderFieldName(k) {
			return nil, fmt.Errorf("invalid HTTP header name %q", k)
		}
		for _, v := range vv {
			if !httpguts.ValidHeaderFieldValue(v) {
				return nil, fmt.Errorf("invalid HTTP header value %q for header %q", v, k)
			}
		}
	}

	// 8.1.2.3 Request Pseudo-Header Fields
	// The :path pseudo-header field includes the path and query parts of the
	// target URI (the path-absolute production and optionally a '?' character
	// followed by the query production (see Sections 3.3 and 3.4 of
	// [RFC3986]).
	w.writeHeader(":authority", host)
	w.writeHeader(":method", req.Method)
	if req.Method != "CONNECT" {
		w.writeHeader(":path", path)
		w.writeHeader(":scheme", req.URL.Scheme)
	}
	if trailers != "" {
		w.writeHeader("trailer", trailers)
	}

	var didUA bool
	for k, vv := range req.Header {
		lowKey := strings.ToLower(k)
		switch lowKey {
		case "host", "content-length":
			// Host is :authority, already sent.
			// Content-Length is automatic, set below.
			continue
		case "connection", "proxy-connection", "transfer-encoding", "upgrade", "keep-alive":
			// Per 8.1.2.2 Connection-Specific Header
			// Fields, don't send connection-specific
			// fields. We have already checked if any
			// are error-worthy so just ignore the rest.
			continue
		case "user-agent":
			// Match Go's http1 behavior: at most one
			// User-Agent. If set to nil or empty string,
			// then omit it. Otherwise if not mentioned,
			// include the default (below).
			didUA = true
			if len(vv) < 1 {
				continue
			}
			vv = vv[:1]
			if vv[0] == "" {
				continue
			}
		}
		for _, v := range vv {
			w.writeHeader(lowKey, v)
		}
	}
	if shouldSendReqContentLength(req.Method, contentLength) {
		w.writeHeader("content-length", strconv.FormatInt(contentLength, 10))
	}
	if addGzipHeader {
		w.writeHeader("accept-encoding", "gzip")
	}
	if !didUA {
		w.writeHeader("user-agent", defaultUserAgent)
	}
	return w.hbuf.Bytes(), nil
}

func (w *requestWriter) writeHeader(name, value string) {
	w.logger.Debugf("http2: Transport encoding header %q = %q", name, value)
	w.henc.WriteField(hpack.HeaderField{Name: name, Value: value})
}

// shouldSendReqContentLength reports whether the http2.Transport should send
// a "content-length" request header. This logic is basically a copy of the net/http
// transferWriter.shouldSendContentLength.
// The contentLength is the corrected contentLength (so 0 means actually 0, not unknown).
// -1 means unknown.
func shouldSendReqContentLength(method string, contentLength int64) bool {
	if contentLength > 0 {
		return true
	}
	if contentLength < 0 {
		return false
	}
	// For zero bodies, whether we send a content-length depends on the method.
	// It also kinda doesn't matter for http2 either way, with END_STREAM.
	switch method {
	case "POST", "PUT", "PATCH":
		return true
	default:
		return false
	}
}

func validPseudoPath(v string) bool {
	return (len(v) > 0 && v[0] == '/' && (len(v) == 1 || v[1] != '/')) || v == "*"
}

// actualContentLength returns a sanitized version of
// req.ContentLength, where 0 actually means zero (not unknown) and -1
// means unknown.
func actualContentLength(req *http.Request) int64 {
	if req.Body == nil {
		return 0
	}
	if req.ContentLength != 0 {
		return req.ContentLength
	}
	return -1
}
