package middleware

import (
	"bytes"
	"io/ioutil"
	"net"
	"net/http"
	"net/url"
	"strings"
	"text/template"
	"time"
)

// This file contains the context and functions available for
// use in the templates.

// Context is the context with which Caddy templates are executed.
type Context struct {
	Root http.FileSystem
	Req  *http.Request
	// This is used to access information about the URL.
	URL *url.URL
}

// Include returns the contents of filename relative to the site root
func (c Context) Include(filename string) (string, error) {
	file, err := c.Root.Open(filename)
	if err != nil {
		return "", err
	}
	defer file.Close()

	body, err := ioutil.ReadAll(file)
	if err != nil {
		return "", err
	}

	tpl, err := template.New(filename).Parse(string(body))
	if err != nil {
		return "", err
	}

	var buf bytes.Buffer
	err = tpl.Execute(&buf, c)
	if err != nil {
		return "", err
	}

	return buf.String(), nil
}

// Now returns the current timestamp in the specified format.
func (c Context) Now(format string) string {
	return time.Now().Format(format)
}

// NowDate returns the current date/time that can be used
// in other time functions.
func (c Context) NowDate() time.Time {
	return time.Now()
}

// Cookie gets the value of a cookie with name name.
func (c Context) Cookie(name string) string {
	cookies := c.Req.Cookies()
	for _, cookie := range cookies {
		if cookie.Name == name {
			return cookie.Value
		}
	}
	return ""
}

// Header gets the value of a request header with field name.
func (c Context) Header(name string) string {
	return c.Req.Header.Get(name)
}

// IP gets the (remote) IP address of the client making the request.
func (c Context) IP() string {
	ip, _, err := net.SplitHostPort(c.Req.RemoteAddr)
	if err != nil {
		return c.Req.RemoteAddr
	}
	return ip
}

// URI returns the raw, unprocessed request URI (including query
// string and hash) obtained directly from the Request-Line of
// the HTTP request.
func (c Context) URI() string {
	return c.Req.RequestURI
}

// Host returns the hostname portion of the Host header
// from the HTTP request.
func (c Context) Host() (string, error) {
	host, _, err := net.SplitHostPort(c.Req.Host)
	if err != nil {
		return "", err
	}
	return host, nil
}

// Port returns the port portion of the Host header if specified.
func (c Context) Port() (string, error) {
	_, port, err := net.SplitHostPort(c.Req.Host)
	if err != nil {
		return "", err
	}
	return port, nil
}

// Method returns the method (GET, POST, etc.) of the request.
func (c Context) Method() string {
	return c.Req.Method
}

// PathMatches returns true if the path portion of the request
// URL matches pattern.
func (c Context) PathMatches(pattern string) bool {
	return Path(c.Req.URL.Path).Matches(pattern)
}

// Truncate truncates the input string to the given length. If
// input is shorter than length, the entire string is returned.
func (c Context) Truncate(input string, length int) string {
	if len(input) > length {
		return input[:length]
	}
	return input
}

// Replace replaces instances of find in input with replacement.
func (c Context) Replace(input, find, replacement string) string {
	return strings.Replace(input, find, replacement, -1)
}
