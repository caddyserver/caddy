package middleware

import (
	"net"
	"net/http"
	"net/url"
	"path"
	"strconv"
	"strings"
	"time"
)

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
	replacements       map[string]string
	customReplacements map[string]string
	emptyValue         string
	responseRecorder   *ResponseRecorder
}

// NewReplacer makes a new replacer based on r and rr which
// are used for request and response placeholders, respectively.
// Request placeholders are created immediately, whereas
// response placeholders are not created until Replace()
// is invoked. rr may be nil if it is not available.
// emptyValue should be the string that is used in place
// of empty string (can still be empty string).
func NewReplacer(r *http.Request, rr *ResponseRecorder, emptyValue string) Replacer {
	rep := &replacer{
		responseRecorder:   rr,
		customReplacements: make(map[string]string),
		replacements: map[string]string{
			"{method}": r.Method,
			"{scheme}": func() string {
				if r.TLS != nil {
					return "https"
				}
				return "http"
			}(),
			"{host}":          r.Host,
			"{path}":          r.URL.Path,
			"{path_escaped}":  url.QueryEscape(r.URL.Path),
			"{query}":         r.URL.RawQuery,
			"{query_escaped}": url.QueryEscape(r.URL.RawQuery),
			"{fragment}":      r.URL.Fragment,
			"{proto}":         r.Proto,
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
			"{uri}":         r.URL.RequestURI(),
			"{uri_escaped}": url.QueryEscape(r.URL.RequestURI()),
			"{when}":        time.Now().Format(timeFormat),
			"{file}": func() string {
				_, file := path.Split(r.URL.Path)
				return file
			}(),
			"{dir}": func() string {
				dir, _ := path.Split(r.URL.Path)
				return dir
			}(),
		},
		emptyValue: emptyValue,
	}

	// Header placeholders (case-insensitive)
	for header, values := range r.Header {
		rep.replacements[headerReplacer+strings.ToLower(header)+"}"] = strings.Join(values, ",")
	}

	return rep
}

// Replace performs a replacement of values on s and returns
// the string with the replaced values.
func (r *replacer) Replace(s string) string {
	// Make response placeholders now
	if r.responseRecorder != nil {
		r.replacements["{status}"] = strconv.Itoa(r.responseRecorder.status)
		r.replacements["{size}"] = strconv.Itoa(r.responseRecorder.size)
		r.replacements["{latency}"] = time.Since(r.responseRecorder.start).String()
	}

	// Include custom placeholders, overwriting existing ones if necessary
	for key, val := range r.customReplacements {
		r.replacements[key] = val
	}

	// Header replacements - these are case-insensitive, so we can't just use strings.Replace()
	for strings.Contains(s, headerReplacer) {
		idxStart := strings.Index(s, headerReplacer)
		endOffset := idxStart + len(headerReplacer)
		idxEnd := strings.Index(s[endOffset:], "}")
		if idxEnd > -1 {
			placeholder := strings.ToLower(s[idxStart : endOffset+idxEnd+1])
			replacement := r.replacements[placeholder]
			if replacement == "" {
				replacement = r.emptyValue
			}
			s = s[:idxStart] + replacement + s[endOffset+idxEnd+1:]
		} else {
			break
		}
	}

	// Regular replacements - these are easier because they're case-sensitive
	for placeholder, replacement := range r.replacements {
		if replacement == "" {
			replacement = r.emptyValue
		}
		s = strings.Replace(s, placeholder, replacement, -1)
	}

	return s
}

// Set sets key to value in the r.customReplacements map.
func (r *replacer) Set(key, value string) {
	r.customReplacements["{"+key+"}"] = value
}

const (
	timeFormat     = "02/Jan/2006:15:04:05 -0700"
	headerReplacer = "{>"
)
