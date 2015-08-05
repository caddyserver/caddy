package middleware

import (
	"net"
	"net/http"
	"strconv"
	"strings"
	"time"
)

// Replacer is a type which can replace placeholder
// substrings in a string with actual values from a
// http.Request and responseRecorder. Always use
// NewReplacer to get one of these.
type Replacer interface {
	Replace(string) string
}

type replacer struct {
	replacements map[string]string
	emptyValue   string
}

// NewReplacer makes a new replacer based on r and rr.
// Do not create a new replacer until r and rr have all
// the needed values, because this function copies those
// values into the replacer. rr may be nil if it is not
// available. emptyValue should be the string that is used
// in place of empty string (can still be empty string).
func NewReplacer(r *http.Request, rr *responseRecorder, emptyValue string) Replacer {
	rep := replacer{
		replacements: map[string]string{
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
			"{uri}": r.URL.RequestURI(),
			"{when}": func() string {
				return time.Now().Format(timeFormat)
			}(),
		},
		emptyValue: emptyValue,
	}
	if rr != nil {
		rep.replacements["{status}"] = strconv.Itoa(rr.status)
		rep.replacements["{size}"] = strconv.Itoa(rr.size)
		rep.replacements["{latency}"] = time.Since(rr.start).String()
	}

	// Header placeholders
	for header, val := range r.Header {
		rep.replacements[headerReplacer+header+"}"] = strings.Join(val, ",")
	}

	return rep
}

// Replace performs a replacement of values on s and returns
// the string with the replaced values.
func (r replacer) Replace(s string) string {
	for placeholder, replacement := range r.replacements {
		if replacement == "" {
			replacement = r.emptyValue
		}
		s = strings.Replace(s, placeholder, replacement, -1)
	}

	// Replace any header placeholders that weren't found
	for strings.Contains(s, headerReplacer) {
		idxStart := strings.Index(s, headerReplacer)
		endOffset := idxStart + len(headerReplacer)
		idxEnd := strings.Index(s[endOffset:], "}")
		if idxEnd > -1 {
			s = s[:idxStart] + r.emptyValue + s[endOffset+idxEnd+1:]
		} else {
			break
		}
	}
	return s
}

const (
	timeFormat     = "02/Jan/2006:15:04:05 -0700"
	headerReplacer = "{>"
)
