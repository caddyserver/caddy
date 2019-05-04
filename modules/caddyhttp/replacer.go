package caddyhttp

import (
	"net/http"
	"strings"
)

type Replacer struct {
	req    *http.Request
	resp   http.ResponseWriter
	custom map[string]string
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
		"host":   r.req.Host,
		"method": r.req.Method,
		"scheme": func() string {
			if r.req.TLS != nil {
				return "https"
			}
			return "http"
		}(),
		"uri": r.req.URL.RequestURI(),
	}

	for field, vals := range r.req.Header {
		m[">"+strings.ToLower(field)] = strings.Join(vals, ",")
	}

	for field, vals := range r.resp.Header() {
		m["<"+strings.ToLower(field)] = strings.Join(vals, ",")
	}

	for _, cookie := range r.req.Cookies() {
		m["~"+cookie.Name] = cookie.Value
	}

	for param, vals := range r.req.URL.Query() {
		m["?"+param] = strings.Join(vals, ",")
	}

	return m
}

const phOpen, phClose = "{", "}"
