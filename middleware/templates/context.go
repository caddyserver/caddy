package templates

import (
	"io/ioutil"
	"net/http"
	"time"
)

// This file contains the context and functions available for
// use in the templates.

// context is the context with which templates are executed.
type context struct {
	root http.FileSystem
	req  *http.Request
}

// Include returns the contents of filename relative to the site root
func (c context) Include(filename string) (string, error) {
	file, err := c.root.Open(filename)
	if err != nil {
		return "", err
	}
	body, err := ioutil.ReadAll(file)
	return string(body), err
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

// RemoteAddr gets the address of the client making the request.
func (c context) RemoteAddr() string {
	return c.req.RemoteAddr
}
