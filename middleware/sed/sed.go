package sed

import (
	"bytes"
	"compress/flate"
	"compress/gzip"
	"errors"
	"io"
	"io/ioutil"
	"net/http"
	"strconv"
	"strings"

	"github.com/mholt/caddy/middleware"
)

var (
	cts  = []string{"text/html"} // TODO (brk0v): only html pages
	size = 1 << 18               // default 256 KB
)

// bufferedWriter buffers responce for replacing content.
type bufferedWriter struct {
	http.ResponseWriter
	Body            *bytes.Buffer
	Code            int             // HTTP code
	Buffered        bool            // Body data buffered
	ContentType     string          // Responce resource's Content-Type
	ContentEncoding string          // Responce resourece's Content-Encoding (might be wrong because of gzip middleware)
	cts             map[string]bool // Content-Types for buffering
	size            int             // Limit for Body buffer
	n               int             // Current Body buffer size
	firstChunk      bool
}

// NewBufferedWriter returns bufferedWriter.
// ct is a list of Content-Type's for buffering.
// size is a size of a buffer.
func NewBufferedWriter(w http.ResponseWriter, ct []string, size int) *bufferedWriter {
	cts := make(map[string]bool)
	for _, c := range ct {
		cts[c] = true
	}
	// TODO (brk0v): allocate buffer from pool?
	return &bufferedWriter{
		ResponseWriter: w,
		Body:           new(bytes.Buffer),
		cts:            cts,
		size:           size,
		firstChunk:     true,
		Code:           http.StatusOK, // default code
	}
}

// checkContentType checks Content-Type for buffering.
func (bw *bufferedWriter) checkContentType() bool {
	// buffering only ct's content types
	ct := bw.ResponseWriter.Header().Get("Content-Type")
	if ct != "" {
		ct = strings.ToLower(ct)
		ct = strings.SplitN(ct, ";", 2)[0]
		if _, ok := bw.cts[ct]; ok {
			bw.Buffered = true
			bw.ContentType = ct
			bw.ContentEncoding = bw.ResponseWriter.Header().Get("Content-Encoding")
			return true
		}
	}
	return false
}

// WriteHeader implements the WriteHeader method of http.ResponseWriter.
func (bw *bufferedWriter) WriteHeader(code int) {
	bw.Code = code
	if bw.firstChunk {
		if !bw.checkContentType() {
			bw.ResponseWriter.WriteHeader(code)
		}
		bw.firstChunk = false
	}
}

// Write implements the write method of http.ResponseWriter.
func (bw *bufferedWriter) Write(buf []byte) (int, error) {
	// do once
	if bw.firstChunk {
		bw.checkContentType()
		bw.firstChunk = false
	}

	// unbuffered write
	if !bw.Buffered {
		return bw.ResponseWriter.Write(buf)
	}

	// check for limit
	if bw.n+len(buf) > bw.size {
		// write buffered data
		if n, err := bw.ResponseWriter.Write(bw.Body.Bytes()); err != nil {
			return n, err
		}
		// drop state
		bw.reset()
		// write new data
		return bw.ResponseWriter.Write(buf)
	}

	n, err := bw.Body.Write(buf)
	bw.n += n
	return n, err
}

var (
	ErrNotBuffered     = errors.New("not buffered write")
	ErrUnknownEncoding = errors.New("unknown encoding")
)

func (bw *bufferedWriter) reset() {
	// drop state
	bw.Buffered = false
	bw.n = 0
	bw.ContentType = ""
	bw.ContentEncoding = ""
	bw.Body.Reset()
}

// Apply returns buffered data (might be nil: e.g. 304 responce) and error.
func (bw *bufferedWriter) Apply(r *http.Request) ([]byte, error) {
	// if not buffered
	if !bw.Buffered {
		return nil, ErrNotBuffered
	}

	// buffered
	var body []byte
	if bw.ContentEncoding != "" {
		if r.Header.Get("Accept-Encoding") == "" {
			// gzip middleware has been already uncompressed data
			body = bw.Body.Bytes()
			return body, nil
		}

		bw.Header().Del("Content-Encoding")
		var ce io.ReadCloser
		var err error
		switch bw.ContentEncoding {
		case "gzip":
			ce, err = gzip.NewReader(bw.Body)
		case "deflate":
			ce = flate.NewReader(bw.Body)
		default:
			// Unknown Content-Encoding so write data and return.
			bw.ResponseWriter.WriteHeader(bw.Code)
			bw.ResponseWriter.Write(body)
			bw.reset()
			return nil, ErrUnknownEncoding
		}

		defer ce.Close()
		if err != nil {
			return nil, err
		}
		body, err = ioutil.ReadAll(ce)
		if err != nil {
			return nil, err
		}
	} else {
		// no Content-Encoding
		body = bw.Body.Bytes()
		return body, nil
	}

	return body, nil
}

type Sed struct {
	Next  middleware.Handler
	Rules []Rule
}

func (s Sed) ServeHTTP(w http.ResponseWriter, r *http.Request) (int, error) {
	for _, rule := range s.Rules {
		if middleware.Path(r.URL.Path).Matches(rule.Url) {

			// Buffering write.
			if rule.Size != 0 {
				size = rule.Size
			}

			bw := NewBufferedWriter(w, cts, size)
			st, err := s.Next.ServeHTTP(bw, r)
			body, bufErr := bw.Apply(r)

			// Not buffered or unknow encoding.
			if bufErr == ErrNotBuffered || bufErr == ErrUnknownEncoding {
				return st, err
			}

			// Rest are errors.
			if bufErr != nil {
				return http.StatusInternalServerError, err
			}

			// Send headers and return immediately (304 and others).
			if body == nil {
				w.WriteHeader(bw.Code)
				return st, err
			}

			// Replace data.
			var oldnew []string
			for _, pattern := range rule.Patterns {
				oldnew = append(oldnew, pattern.Find)
				oldnew = append(oldnew, pattern.Replace)
			}
			replacer := strings.NewReplacer(oldnew...)
			data := replacer.Replace(string(body))

			// Update Content-Length if we have Content-Length.
			if bw.Header().Get("Content-Length") != "" {
				w.Header().Set("Content-Length", strconv.Itoa(len(data)))
			}

			// Send data.
			w.WriteHeader(bw.Code)
			w.Write([]byte(data))
			return st, err
		}
	}

	return s.Next.ServeHTTP(w, r)
}

type (
	Rule struct {
		Url      string
		Patterns []Pattern
		Size     int
	}

	Pattern struct {
		Find    string
		Replace string
	}
)
