package caddyhttp

import (
	"net"
	"net/http"
	"os"
	"strings"

	"bitbucket.org/lightcodelabs/caddy2"
)

// Replacer can replace values in strings based
// on a request and/or response writer. The zero
// Replacer is not valid; use NewReplacer() to
// initialize one.
type Replacer struct {
	req    *http.Request
	resp   http.ResponseWriter
	custom map[string]string
}

// NewReplacer makes a new Replacer, initializing all necessary
// fields. The request and response writer are optional, but
// necessary for most replacements to work.
func NewReplacer(req *http.Request, rw http.ResponseWriter) *Replacer {
	return &Replacer{
		req:    req,
		resp:   rw,
		custom: make(map[string]string),
	}
}

// Map sets a custom variable mapping to a value.
func (r *Replacer) Map(variable, value string) {
	r.custom[variable] = value
}

// Replace replaces placeholders in input with the value. If
// the value is empty string, the placeholder is substituted
// with the value empty.
func (r *Replacer) Replace(input, empty string) string {
	if !strings.Contains(input, phOpen) {
		return input
	}

	input = r.replaceAll(input, empty, r.defaults())
	input = r.replaceAll(input, empty, r.custom)

	return input
}

func (r *Replacer) replaceAll(input, empty string, mapping map[string]string) string {
	for key, val := range mapping {
		if val == "" {
			val = empty
		}
		input = strings.ReplaceAll(input, phOpen+key+phClose, val)
	}
	return input
}

func (r *Replacer) defaults() map[string]string {
	m := map[string]string{
		"system.hostname": func() string {
			// OK if there is an error; just return empty string
			name, _ := os.Hostname()
			return name
		}(),
	}

	if r.req != nil {
		m["request.host"] = func() string {
			host, _, err := net.SplitHostPort(r.req.Host)
			if err != nil {
				return r.req.Host // OK; there probably was no port
			}
			return host
		}()
		m["request.hostport"] = r.req.Host // may include both host and port
		m["request.method"] = r.req.Method
		m["request.port"] = func() string {
			// if there is no port, there will be an error; in
			// that case, port is the empty string anyway
			_, port, _ := net.SplitHostPort(r.req.Host)
			return port
		}()
		m["request.scheme"] = func() string {
			if r.req.TLS != nil {
				return "https"
			}
			return "http"
		}()
		m["request.uri"] = r.req.URL.RequestURI()
		m["request.uri.path"] = r.req.URL.Path

		for field, vals := range r.req.Header {
			m["request.header."+strings.ToLower(field)] = strings.Join(vals, ",")
		}
		for _, cookie := range r.req.Cookies() {
			m["request.cookie."+cookie.Name] = cookie.Value
		}
		for param, vals := range r.req.URL.Query() {
			m["request.uri.query."+param] = strings.Join(vals, ",")
		}
	}

	if r.resp != nil {
		for field, vals := range r.resp.Header() {
			m["response.header."+strings.ToLower(field)] = strings.Join(vals, ",")
		}
	}

	return m
}

const phOpen, phClose = "{", "}"

// ReplacerCtxKey is the context key for the request's replacer.
const ReplacerCtxKey caddy2.CtxKey = "replacer"
