package templates

import (
	"bytes"
	"io/ioutil"
	"net"
	"net/http"
	"net/url"
	"text/template"
	"time"

	"github.com/mholt/caddy/middleware"
)

// This file contains the context and functions available for
// use in the templates.

// context is the context with which templates are executed.
type context struct {
	root http.FileSystem
	req  *http.Request
	URL  *url.URL
}

// Include returns the contents of filename relative to the site root
func (c context) Include(filename string) (string, error) {
	file, err := c.root.Open(filename)
	if err != nil {
		return "", err
	}

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

// Date returns the current timestamp in the specified format
func (c context) Date(format string) string {
	return time.Now().Format(format)
}

// Cookie gets the value of a cookie with name name.
func (c context) Cookie(name string) string {
	cookies := c.req.Cookies()
	for _, cookie := range cookies {
		if cookie.Name == name {
			return cookie.Value
		}
	}
	return ""
}

// Header gets the value of a request header with field name.
func (c context) Header(name string) string {
	return c.req.Header.Get(name)
}

// IP gets the (remote) IP address of the client making the request.
func (c context) IP() string {
	ip, _, err := net.SplitHostPort(c.req.RemoteAddr)
	if err != nil {
		return c.req.RemoteAddr
	}
	return ip
}

// URI returns the raw, unprocessed request URI (including query
// string and hash) obtained directly from the Request-Line of
// the HTTP request.
func (c context) URI() string {
	return c.req.RequestURI
}

// Host returns the hostname portion of the Host header
// from the HTTP request.
func (c context) Host() (string, error) {
	host, _, err := net.SplitHostPort(c.req.Host)
	if err != nil {
		return "", err
	}
	return host, nil
}

// Port returns the port portion of the Host header if specified.
func (c context) Port() (string, error) {
	_, port, err := net.SplitHostPort(c.req.Host)
	if err != nil {
		return "", err
	}
	return port, nil
}

// Method returns the method (GET, POST, etc.) of the request.
func (c context) Method() string {
	return c.req.Method
}

// PathMatches returns true if the path portion of the request
// URL matches pattern.
func (c context) PathMatches(pattern string) bool {
	return middleware.Path(c.req.URL.Path).Matches(pattern)
}
