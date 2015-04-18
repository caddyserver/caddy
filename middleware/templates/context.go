package templates

import (
	"io/ioutil"
	"net/http"
)

// This file contains the context and functions available for
// use in the templates.

// context is the context with which templates are executed.
type context struct {
	root http.FileSystem
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
