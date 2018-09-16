// Copyright 2015 Light Code Labs, LLC
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

package httpserver

import (
	"bytes"
	"crypto/sha256"
	"crypto/x509"
	"encoding/pem"
	"fmt"
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
	"github.com/mholt/caddy/caddytls"
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
	repl := &replacer{
		request:          r,
		responseRecorder: rr,
		emptyValue:       emptyValue,
	}

	// extract customReplacements from a request replacer when present.
	if existing, ok := r.Context().Value(ReplacerCtxKey).(*replacer); ok {
		repl.requestBody = existing.requestBody
		repl.customReplacements = existing.customReplacements
	} else {
		// if there is no existing replacer, build one from scratch.
		rb := newLimitWriter(MaxLogBodySize)
		if r.Body != nil {
			r.Body = struct {
				io.Reader
				io.Closer
			}{io.TeeReader(r.Body, rb), io.Closer(r.Body)}
		}
		repl.requestBody = rb
		repl.customReplacements = make(map[string]string)
	}

	return repl
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

// unescapeBraces finds escaped braces in s and returns
// a string with those braces unescaped.
func unescapeBraces(s string) string {
	s = strings.Replace(s, "\\{", "{", -1)
	s = strings.Replace(s, "\\}", "}", -1)
	return s
}

// Replace performs a replacement of values on s and returns
// the string with the replaced values.
func (r *replacer) Replace(s string) string {
	// Do not attempt replacements if no placeholder is found.
	if !strings.ContainsAny(s, "{}") {
		return s
	}

	result := ""
Placeholders: // process each placeholder in sequence
	for {
		var idxStart, idxEnd int

		idxOffset := 0
		for { // find first unescaped opening brace
			searchSpace := s[idxOffset:]
			idxStart = strings.Index(searchSpace, "{")
			if idxStart == -1 {
				// no more placeholders
				break Placeholders
			}
			if idxStart == 0 || searchSpace[idxStart-1] != '\\' {
				// preceding character is not an escape
				idxStart += idxOffset
				break
			}
			// the brace we found was escaped
			// search the rest of the string next
			idxOffset += idxStart + 1
		}

		idxOffset = 0
		for { // find first unescaped closing brace
			searchSpace := s[idxStart+idxOffset:]
			idxEnd = strings.Index(searchSpace, "}")
			if idxEnd == -1 {
				// unpaired placeholder
				break Placeholders
			}
			if idxEnd == 0 || searchSpace[idxEnd-1] != '\\' {
				// preceding character is not an escape
				idxEnd += idxOffset + idxStart
				break
			}
			// the brace we found was escaped
			// search the rest of the string next
			idxOffset += idxEnd + 1
		}

		// get a replacement for the unescaped placeholder
		placeholder := unescapeBraces(s[idxStart : idxEnd+1])
		replacement := r.getSubstitution(placeholder)

		// append unescaped prefix + replacement
		result += strings.TrimPrefix(unescapeBraces(s[:idxStart]), "\\") + replacement

		// strip out scanned parts
		s = s[idxEnd+1:]
	}

	// append unscanned parts
	return result + unescapeBraces(s)
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

// getPeerCert returns peer certificate
func (r *replacer) getPeerCert() *x509.Certificate {
	if r.request.TLS != nil && len(r.request.TLS.PeerCertificates) > 0 {
		return r.request.TLS.PeerCertificates[0]
	}

	return nil
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
	// search response headers then
	if r.responseRecorder != nil && key[1] == '<' {
		want := key[2 : len(key)-1]
		for key, values := range r.responseRecorder.Header() {
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
		u, _ := r.request.Context().Value(OriginalURLCtxKey).(url.URL)
		return u.Path
	case "{path_escaped}":
		u, _ := r.request.Context().Value(OriginalURLCtxKey).(url.URL)
		return url.QueryEscape(u.Path)
	case "{request_id}":
		reqid, _ := r.request.Context().Value(RequestIDCtxKey).(string)
		return reqid
	case "{rewrite_path}":
		return r.request.URL.Path
	case "{rewrite_path_escaped}":
		return url.QueryEscape(r.request.URL.Path)
	case "{query}":
		u, _ := r.request.Context().Value(OriginalURLCtxKey).(url.URL)
		return u.RawQuery
	case "{query_escaped}":
		u, _ := r.request.Context().Value(OriginalURLCtxKey).(url.URL)
		return url.QueryEscape(u.RawQuery)
	case "{fragment}":
		u, _ := r.request.Context().Value(OriginalURLCtxKey).(url.URL)
		return u.Fragment
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
		u, _ := r.request.Context().Value(OriginalURLCtxKey).(url.URL)
		return u.RequestURI()
	case "{uri_escaped}":
		u, _ := r.request.Context().Value(OriginalURLCtxKey).(url.URL)
		return url.QueryEscape(u.RequestURI())
	case "{rewrite_uri}":
		return r.request.URL.RequestURI()
	case "{rewrite_uri_escaped}":
		return url.QueryEscape(r.request.URL.RequestURI())
	case "{when}":
		return now().Format(timeFormat)
	case "{when_iso}":
		return now().UTC().Format(timeFormatISOUTC)
	case "{when_unix}":
		return strconv.FormatInt(now().Unix(), 10)
	case "{when_unix_ms}":
		return strconv.FormatInt(nanoToMilliseconds(now().UnixNano()), 10)
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
			if err == ErrMaxBytesExceeded {
				return r.emptyValue
			}
		}
		return requestReplacer.Replace(r.requestBody.String())
	case "{mitm}":
		if val, ok := r.request.Context().Value(caddy.CtxKey("mitm")).(bool); ok {
			if val {
				return "likely"
			}
			return "unlikely"
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
	case "{tls_protocol}":
		if r.request.TLS != nil {
			if name, err := caddytls.GetSupportedProtocolName(r.request.TLS.Version); err == nil {
				return name
			} else {
				return "tls" // this should never happen, but guard in case
			}
		}
		return r.emptyValue // because not using a secure channel
	case "{tls_cipher}":
		if r.request.TLS != nil {
			if name, err := caddytls.GetSupportedCipherName(r.request.TLS.CipherSuite); err == nil {
				return name
			} else {
				return "UNKNOWN" // this should never happen, but guard in case
			}
		}
		return r.emptyValue
	case "{tls_client_escaped_cert}":
		cert := r.getPeerCert()
		if cert != nil {
			pemBlock := pem.Block{
				Type:  "CERTIFICATE",
				Bytes: cert.Raw,
			}
			return url.QueryEscape(string(pem.EncodeToMemory(&pemBlock)))
		}
		return r.emptyValue
	case "{tls_client_fingerprint}":
		cert := r.getPeerCert()
		if cert != nil {
			return fmt.Sprintf("%x", sha256.Sum256(cert.Raw))
		}
		return r.emptyValue
	case "{tls_client_i_dn}":
		cert := r.getPeerCert()
		if cert != nil {
			return cert.Issuer.String()
		}
		return r.emptyValue
	case "{tls_client_raw_cert}":
		cert := r.getPeerCert()
		if cert != nil {
			return string(cert.Raw)
		}
		return r.emptyValue
	case "{tls_client_s_dn}":
		cert := r.getPeerCert()
		if cert != nil {
			return cert.Subject.String()
		}
		return r.emptyValue
	case "{tls_client_serial}":
		cert := r.getPeerCert()
		if cert != nil {
			return fmt.Sprintf("%x", cert.SerialNumber)
		}
		return r.emptyValue
	case "{tls_client_v_end}":
		cert := r.getPeerCert()
		if cert != nil {
			return cert.NotAfter.In(time.UTC).Format("Jan 02 15:04:05 2006 MST")
		}
		return r.emptyValue
	case "{tls_client_v_remain}":
		cert := r.getPeerCert()
		if cert != nil {
			now := time.Now().In(time.UTC)
			days := int64(cert.NotAfter.Sub(now).Seconds() / 86400)
			return strconv.FormatInt(days, 10)
		}
		return r.emptyValue
	case "{tls_client_v_start}":
		cert := r.getPeerCert()
		if cert != nil {
			return cert.NotBefore.Format("Jan 02 15:04:05 2006 MST")
		}
		return r.emptyValue
	default:
		// {labelN}
		if strings.HasPrefix(key, "{label") {
			nStr := key[6 : len(key)-1] // get the integer N in "{labelN}"
			n, err := strconv.Atoi(nStr)
			if err != nil || n < 1 {
				return r.emptyValue
			}
			labels := strings.Split(r.request.Host, ".")
			if n > len(labels) {
				return r.emptyValue
			}
			return labels[n-1]
		}
	}

	return r.emptyValue
}

func nanoToMilliseconds(d int64) int64 {
	return d / 1e6
}

// convertToMilliseconds returns the number of milliseconds in the given duration
func convertToMilliseconds(d time.Duration) int64 {
	return nanoToMilliseconds(d.Nanoseconds())
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
