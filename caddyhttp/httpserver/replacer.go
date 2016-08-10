package httpserver

import (
	"bytes"
	"io/ioutil"
	"log"
	"net"
	"net/http"
	"net/http/httputil"
	"net/url"
	"os"
	"path"
	"strconv"
	"strings"
	"time"
)

// requestReplacer is a strings.Replacer which is used to
// encode literal \r and \n characters and keep everything
// on one line
var requestReplacer = strings.NewReplacer(
	"\r", "\\r",
	"\n", "\\n",
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
	replacements       map[string]func() string
	customReplacements map[string]func() string
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
		customReplacements: make(map[string]func() string),
		replacements: map[string]func() string{
			"{method}": func() string { return r.Method },
			"{scheme}": func() string {
				if r.TLS != nil {
					return "https"
				}
				return "http"
			},
			"{hostname}": func() string {
				name, err := os.Hostname()
				if err != nil {
					return ""
				}
				return name
			},
			"{host}": func() string { return r.Host },
			"{hostonly}": func() string {
				host, _, err := net.SplitHostPort(r.Host)
				if err != nil {
					return r.Host
				}
				return host
			},
			"{path}":          func() string { return r.URL.Path },
			"{path_escaped}":  func() string { return url.QueryEscape(r.URL.Path) },
			"{query}":         func() string { return r.URL.RawQuery },
			"{query_escaped}": func() string { return url.QueryEscape(r.URL.RawQuery) },
			"{fragment}":      func() string { return r.URL.Fragment },
			"{proto}":         func() string { return r.Proto },
			"{remote}": func() string {
				if fwdFor := r.Header.Get("X-Forwarded-For"); fwdFor != "" {
					return fwdFor
				}
				host, _, err := net.SplitHostPort(r.RemoteAddr)
				if err != nil {
					return r.RemoteAddr
				}
				return host
			},
			"{port}": func() string {
				_, port, err := net.SplitHostPort(r.RemoteAddr)
				if err != nil {
					return ""
				}
				return port
			},
			"{uri}":         func() string { return r.URL.RequestURI() },
			"{uri_escaped}": func() string { return url.QueryEscape(r.URL.RequestURI()) },
			"{when}":        func() string { return time.Now().Format(timeFormat) },
			"{file}": func() string {
				_, file := path.Split(r.URL.Path)
				return file
			},
			"{dir}": func() string {
				dir, _ := path.Split(r.URL.Path)
				return dir
			},
			"{request}": func() string {
				dump, err := httputil.DumpRequest(r, false)
				if err != nil {
					return ""
				}

				return requestReplacer.Replace(string(dump))
			},
			"{request_body}": func() string {
				if !canLogRequest(r) {
					return ""
				}

				body, err := readRequestBody(r)
				if err != nil {
					log.Printf("[WARNING] Cannot copy request body %v", err)
					return ""
				}

				return string(body)
			},
		},
		emptyValue: emptyValue,
	}

	// Header placeholders (case-insensitive)
	for header, values := range r.Header {
		values := values
		rep.replacements[headerReplacer+strings.ToLower(header)+"}"] = func() string { return strings.Join(values, ",") }
	}

	return rep
}

func canLogRequest(r *http.Request) (canLog bool) {
	if r.Method == "POST" || r.Method == "PUT" {
		for _, cType := range r.Header[headerContentType] {
			// the cType could have charset and other info
			if strings.Index(cType, contentTypeJSON) > -1 || strings.Index(cType, contentTypeXML) > -1 {
				canLog = true
				break
			}
		}
	}
	return
}

// readRequestBody reads the request body and sets a
// new io.ReadCloser that has not yet been read.
func readRequestBody(r *http.Request) ([]byte, error) {
	body, err := ioutil.ReadAll(r.Body)
	if err != nil {
		return nil, err
	}
	// Create a new ReadCloser to keep the body from being drained.
	r.Body = ioutil.NopCloser(bytes.NewBuffer(body))
	return body, nil
}

// Replace performs a replacement of values on s and returns
// the string with the replaced values.
func (r *replacer) Replace(s string) string {
	// Do not attempt replacements if no placeholder is found.
	if !strings.ContainsAny(s, "{}") {
		return s
	}

	// Make response placeholders now
	if r.responseRecorder != nil {
		r.replacements["{status}"] = func() string { return strconv.Itoa(r.responseRecorder.status) }
		r.replacements["{size}"] = func() string { return strconv.Itoa(r.responseRecorder.size) }
		r.replacements["{latency}"] = func() string {
			dur := time.Since(r.responseRecorder.start)
			return roundDuration(dur).String()
		}
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
			replacement := ""
			if getReplacement, ok := r.replacements[placeholder]; ok {
				replacement = getReplacement()
			}
			if replacement == "" {
				replacement = r.emptyValue
			}
			s = s[:idxStart] + replacement + s[endOffset+idxEnd+1:]
		} else {
			break
		}
	}

	// Regular replacements - these are easier because they're case-sensitive
	for placeholder, getReplacement := range r.replacements {
		if !strings.Contains(s, placeholder) {
			continue
		}
		replacement := getReplacement()
		if replacement == "" {
			replacement = r.emptyValue
		}
		s = strings.Replace(s, placeholder, replacement, -1)
	}

	return s
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

// Set sets key to value in the r.customReplacements map.
func (r *replacer) Set(key, value string) {
	r.customReplacements["{"+key+"}"] = func() string { return value }
}

const (
	timeFormat        = "02/Jan/2006:15:04:05 -0700"
	headerReplacer    = "{>"
	headerContentType = "Content-Type"
	contentTypeJSON   = "application/json"
	contentTypeXML    = "application/xml"
)
