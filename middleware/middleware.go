// Package middleware provides some types and functions common among middleware.
package middleware

import (
	"net/http"
	"path/filepath"
)

type (
	// Middleware is the middle layer which represents the traditional
	// idea of middleware: it chains one Handler to the next by being
	// passed the next Handler in the chain.
	Middleware func(Handler) Handler

	// Handler is like http.Handler except ServeHTTP returns a status code
	// and an error. The status code is for the client's benefit; the error
	// value is for the server's benefit. The status code will be sent to
	// the client while the error value will be logged privately. Sometimes,
	// an error status code (4xx or 5xx) may be returned with a nil error
	// when there is no reason to log the error on the server.
	//
	// If a HandlerFunc returns an error (status >= 400), it should NOT
	// write to the response. This philosophy makes middleware.Handler
	// different from http.Handler: error handling should happen at the
	// application layer or in dedicated error-handling middleware only
	// rather than with an "every middleware for itself" paradigm.
	//
	// The application or error-handling middleware should incorporate logic
	// to ensure that the client always gets a proper response according to
	// the status code. For security reasons, it should probably not reveal
	// the actual error message. (Instead it should be logged, for example.)
	//
	// Handlers which do write to the response should return a status value
	// < 400 as a signal that a response has been written. In other words,
	// only error-handling middleware or the application will write to the
	// response for a status code >= 400. When ANY handler writes to the
	// response, it should return a status code < 400 to signal others to
	// NOT write to the response again, which would be erroneous.
	Handler interface {
		ServeHTTP(http.ResponseWriter, *http.Request) (int, error)
	}

	// HandlerFunc is a convenience type like http.HandlerFunc, except
	// ServeHTTP returns a status code and an error. See Handler
	// documentation for more information.
	HandlerFunc func(http.ResponseWriter, *http.Request) (int, error)
)

// ServeHTTP implements the Handler interface.
func (f HandlerFunc) ServeHTTP(w http.ResponseWriter, r *http.Request) (int, error) {
	return f(w, r)
}

// IndexFile looks for a file in /root/fpath/indexFile for each string
// in indexFiles. If an index file is found, it returns the root-relative
// path to the file and true. If no index file is found, empty string
// and false is returned. fpath must end in a forward slash '/'
// otherwise no index files will be tried (directory paths must end
// in a forward slash according to HTTP).
func IndexFile(root http.FileSystem, fpath string, indexFiles []string) (string, bool) {
	if fpath[len(fpath)-1] != '/' || root == nil {
		return "", false
	}
	for _, indexFile := range indexFiles {
		fp := filepath.Join(fpath, indexFile)
		f, err := root.Open(fp)
		if err == nil {
			f.Close()
			return fp, true
		}
	}
	return "", false
}
