package middleware

import (
	"net"
	"net/http"
	"strconv"
	"strings"
	"time"
)

// replacer is a type which can replace placeholder
// substrings in a string with actual values from a
// http.Request and responseRecorder. Always use
// NewReplacer to get one of these.
type replacer map[string]string

// NewReplacer makes a new replacer based on r and rr.
// Do not create a new replacer until r and rr have all
// the needed values, because this function copies those
// values into the replacer.
func NewReplacer(r *http.Request, rr *responseRecorder) replacer {
	rep := replacer{
		"{method}": r.Method,
		"{scheme}": func() string {
			if r.TLS != nil {
				return "https"
			}
			return "http"
		}(),
		"{host}":     r.Host,
		"{path}":     r.URL.Path,
		"{query}":    r.URL.RawQuery,
		"{fragment}": r.URL.Fragment,
		"{proto}":    r.Proto,
		"{remote}": func() string {
			if fwdFor := r.Header.Get("X-Forwarded-For"); fwdFor != "" {
				return fwdFor
			}
			host, _, err := net.SplitHostPort(r.RemoteAddr)
			if err != nil {
				return r.RemoteAddr
			}
			return host
		}(),
		"{port}": func() string {
			_, port, err := net.SplitHostPort(r.RemoteAddr)
			if err != nil {
				return ""
			}
			return port
		}(),
		"{uri}": r.RequestURI,
		"{when}": func() string {
			return time.Now().Format(timeFormat)
		}(),
	}
	if rr != nil {
		rep["{status}"] = strconv.Itoa(rr.status)
		rep["{size}"] = strconv.Itoa(rr.size)
		rep["{latency}"] = time.Since(rr.start).String()
	}

	// Header placeholders
	for header, val := range r.Header {
		rep[headerReplacer+header+"}"] = strings.Join(val, ",")
	}

	return rep
}

// Replace performs a replacement of values on s and returns
// the string with the replaced values.
func (r replacer) Replace(s string) string {
	for placeholder, replacement := range r {
		if replacement == "" {
			replacement = EmptyStringReplacer
		}
		s = strings.Replace(s, placeholder, replacement, -1)
	}

	// Replace any header placeholders that weren't found
	for strings.Contains(s, headerReplacer) {
		idxStart := strings.Index(s, headerReplacer)
		endOffset := idxStart + len(headerReplacer)
		idxEnd := strings.Index(s[endOffset:], "}")
		if idxEnd > -1 {
			s = s[:idxStart] + EmptyStringReplacer + s[endOffset+idxEnd+1:]
		} else {
			break
		}
	}
	return s
}

const (
	timeFormat          = "02/Jan/2006:15:04:05 -0700"
	headerReplacer      = "{>"
	EmptyStringReplacer = "-"
)
