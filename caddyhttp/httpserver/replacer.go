package httpserver

import (
	"bytes"
	"io"
	"io/ioutil"
	"net"
	"net/http"
	"net/http/httputil"
	"net/url"
	"os"
	"path"
	"strconv"
	"strings"
	"time"

	"github.com/mholt/caddy"
)

// requestReplacer is a strings.Replacer which is used to
// encode literal \r and \n characters and keep everything
// on one line
var requestReplacer = strings.NewReplacer(
	"\r", "\\r",
	"\n", "\\n",
)

var now = time.Now

// Replacer is a type which can replace placeholder
// substrings in a string with actual values from a
// http.Request and ResponseRecorder. Always use
// NewReplacer to get one of these. Any placeholders
// made with Set() should overwrite existing values if
// the key is already used.
type Replacer interface {
	Replace(string) string
	Set(key, value string)
}

// replacer implements Replacer. customReplacements
// is used to store custom replacements created with
// Set() until the time of replacement, at which point
// they will be used to overwrite other replacements
// if there is a name conflict.
type replacer struct {
	customReplacements map[string]string
	emptyValue         string
	responseRecorder   *ResponseRecorder
	request            *http.Request
	requestBody        *limitWriter
}

type limitWriter struct {
	w      bytes.Buffer
	remain int
}

func newLimitWriter(max int) *limitWriter {
	return &limitWriter{
		w:      bytes.Buffer{},
		remain: max,
	}
}

func (lw *limitWriter) Write(p []byte) (int, error) {
	// skip if we are full
	if lw.remain <= 0 {
		return len(p), nil
	}
	if n := len(p); n > lw.remain {
		p = p[:lw.remain]
	}
	n, err := lw.w.Write(p)
	lw.remain -= n
	return n, err
}

func (lw *limitWriter) String() string {
	return lw.w.String()
}

// NewReplacer makes a new replacer based on r and rr which
// are used for request and response placeholders, respectively.
// Request placeholders are created immediately, whereas
// response placeholders are not created until Replace()
// is invoked. rr may be nil if it is not available.
// emptyValue should be the string that is used in place
// of empty string (can still be empty string).
func NewReplacer(r *http.Request, rr *ResponseRecorder, emptyValue string) Replacer {
	rb := newLimitWriter(MaxLogBodySize)
	if r.Body != nil {
		r.Body = struct {
			io.Reader
			io.Closer
		}{io.TeeReader(r.Body, rb), io.Closer(r.Body)}
	}
	return &replacer{
		request:            r,
		requestBody:        rb,
		responseRecorder:   rr,
		customReplacements: make(map[string]string),
		emptyValue:         emptyValue,
	}
}

func canLogRequest(r *http.Request) bool {
	if r.Method == "POST" || r.Method == "PUT" {
		for _, cType := range r.Header[headerContentType] {
			// the cType could have charset and other info
			if strings.Contains(cType, contentTypeJSON) || strings.Contains(cType, contentTypeXML) {
				return true
			}
		}
	}
	return false
}

// Replace performs a replacement of values on s and returns
// the string with the replaced values.
func (r *replacer) Replace(s string) string {
	// Do not attempt replacements if no placeholder is found.
	if !strings.ContainsAny(s, "{}") {
		return s
	}

	result := ""
	for {
		idxStart := strings.Index(s, "{")
		if idxStart == -1 {
			// no placeholder anymore
			break
		}
		idxEnd := strings.Index(s[idxStart:], "}")
		if idxEnd == -1 {
			// unpaired placeholder
			break
		}
		idxEnd += idxStart

		// get a replacement
		placeholder := s[idxStart : idxEnd+1]
		replacement := r.getSubstitution(placeholder)

		// append prefix + replacement
		result += s[:idxStart] + replacement

		// strip out scanned parts
		s = s[idxEnd+1:]
	}

	// append unscanned parts
	return result + s
}

func roundDuration(d time.Duration) time.Duration {
	if d >= time.Millisecond {
		return round(d, time.Millisecond)
	} else if d >= time.Microsecond {
		return round(d, time.Microsecond)
	}

	return d
}

// round rounds d to the nearest r
func round(d, r time.Duration) time.Duration {
	if r <= 0 {
		return d
	}
	neg := d < 0
	if neg {
		d = -d
	}
	if m := d % r; m+m < r {
		d = d - m
	} else {
		d = d + r - m
	}
	if neg {
		return -d
	}
	return d
}

// getSubstitution retrieves value from corresponding key
func (r *replacer) getSubstitution(key string) string {
	// search custom replacements first
	if value, ok := r.customReplacements[key]; ok {
		return value
	}

	// search request headers then
	if key[1] == '>' {
		want := key[2 : len(key)-1]
		for key, values := range r.request.Header {
			// Header placeholders (case-insensitive)
			if strings.EqualFold(key, want) {
				return strings.Join(values, ",")
			}
		}
	}
	// next check for cookies
	if key[1] == '~' {
		name := key[2 : len(key)-1]
		if cookie, err := r.request.Cookie(name); err == nil {
			return cookie.Value
		}
	}
	// next check for query argument
	if key[1] == '?' {
		query := r.request.URL.Query()
		name := key[2 : len(key)-1]
		return query.Get(name)
	}

	// search default replacements in the end
	switch key {
	case "{method}":
		return r.request.Method
	case "{scheme}":
		if r.request.TLS != nil {
			return "https"
		}
		return "http"
	case "{hostname}":
		name, err := os.Hostname()
		if err != nil {
			return r.emptyValue
		}
		return name
	case "{host}":
		return r.request.Host
	case "{hostonly}":
		host, _, err := net.SplitHostPort(r.request.Host)
		if err != nil {
			return r.request.Host
		}
		return host
	case "{path}":
		// if a rewrite has happened, the original URI should be used as the path
		// rather than the rewritten URI
		var path string
		origpath, _ := r.request.Context().Value(URIxRewriteCtxKey).(string)
		if origpath == "" {
			path = r.request.URL.Path
		} else {
			parsedURL, _ := url.Parse(origpath)
			path = parsedURL.Path
		}
		return path
	case "{path_escaped}":
		var path string
		origpath, _ := r.request.Context().Value(URIxRewriteCtxKey).(string)
		if origpath == "" {
			path = r.request.URL.Path
		} else {
			parsedURL, _ := url.Parse(origpath)
			path = parsedURL.Path
		}
		return url.QueryEscape(path)
	case "{rewrite_path}":
		return r.request.URL.Path
	case "{rewrite_path_escaped}":
		return url.QueryEscape(r.request.URL.Path)
	case "{query}":
		return r.request.URL.RawQuery
	case "{query_escaped}":
		return url.QueryEscape(r.request.URL.RawQuery)
	case "{fragment}":
		return r.request.URL.Fragment
	case "{proto}":
		return r.request.Proto
	case "{remote}":
		host, _, err := net.SplitHostPort(r.request.RemoteAddr)
		if err != nil {
			return r.request.RemoteAddr
		}
		return host
	case "{port}":
		_, port, err := net.SplitHostPort(r.request.RemoteAddr)
		if err != nil {
			return r.emptyValue
		}
		return port
	case "{uri}":
		uri, _ := r.request.Context().Value(URIxRewriteCtxKey).(string)
		if uri == "" {
			uri = r.request.URL.RequestURI()
		}
		return uri
	case "{uri_escaped}":
		uri, _ := r.request.Context().Value(URIxRewriteCtxKey).(string)
		if uri == "" {
			uri = r.request.URL.RequestURI()
		}
		return url.QueryEscape(uri)
	case "{rewrite_uri}":
		return r.request.URL.RequestURI()
	case "{rewrite_uri_escaped}":
		return url.QueryEscape(r.request.URL.RequestURI())
	case "{when}":
		return now().Format(timeFormat)
	case "{when_iso}":
		return now().UTC().Format(timeFormatISOUTC)
	case "{file}":
		_, file := path.Split(r.request.URL.Path)
		return file
	case "{dir}":
		dir, _ := path.Split(r.request.URL.Path)
		return dir
	case "{request}":
		dump, err := httputil.DumpRequest(r.request, false)
		if err != nil {
			return r.emptyValue
		}
		return requestReplacer.Replace(string(dump))
	case "{request_body}":
		if !canLogRequest(r.request) {
			return r.emptyValue
		}
		_, err := ioutil.ReadAll(r.request.Body)
		if err != nil {
			if _, ok := err.(MaxBytesExceeded); ok {
				return r.emptyValue
			}
		}
		return requestReplacer.Replace(r.requestBody.String())
	case "{mitm}":
		if val, ok := r.request.Context().Value(caddy.CtxKey("mitm")).(bool); ok {
			if val {
				return "likely"
			} else {
				return "unlikely"
			}
		}
		return "unknown"
	case "{status}":
		if r.responseRecorder == nil {
			return r.emptyValue
		}
		return strconv.Itoa(r.responseRecorder.status)
	case "{size}":
		if r.responseRecorder == nil {
			return r.emptyValue
		}
		return strconv.Itoa(r.responseRecorder.size)
	case "{latency}":
		if r.responseRecorder == nil {
			return r.emptyValue
		}
		return roundDuration(time.Since(r.responseRecorder.start)).String()
	case "{latency_ms}":
		if r.responseRecorder == nil {
			return r.emptyValue
		}
		elapsedDuration := time.Since(r.responseRecorder.start)
		return strconv.FormatInt(convertToMilliseconds(elapsedDuration), 10)
	}

	return r.emptyValue
}

//convertToMilliseconds returns the number of milliseconds in the given duration
func convertToMilliseconds(d time.Duration) int64 {
	return d.Nanoseconds() / 1e6
}

// Set sets key to value in the r.customReplacements map.
func (r *replacer) Set(key, value string) {
	r.customReplacements["{"+key+"}"] = value
}

const (
	timeFormat        = "02/Jan/2006:15:04:05 -0700"
	timeFormatISOUTC  = "2006-01-02T15:04:05Z" // ISO 8601 with timezone to be assumed as UTC
	headerContentType = "Content-Type"
	contentTypeJSON   = "application/json"
	contentTypeXML    = "application/xml"
	// MaxLogBodySize limits the size of logged request's body
	MaxLogBodySize = 100 * 1024
)
