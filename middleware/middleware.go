// Package middleware provides some types and functions common among middleware.
package middleware

import (
	"net/http"
	"path"
	"time"
)

type (
	// Middleware is the middle layer which represents the traditional
	// idea of middleware: it chains one Handler to the next by being
	// passed the next Handler in the chain.
	Middleware func(Handler) Handler

	// Handler is like http.Handler except ServeHTTP may return a status
	// code and/or error.
	//
	// If ServeHTTP writes to the response body, it should return a status
	// code of 0. This signals to other handlers above it that the response
	// body is already written, and that they should not write to it also.
	//
	// If ServeHTTP encounters an error, it should return the error value
	// so it can be logged by designated error-handling middleware.
	//
	// If writing a response after calling another ServeHTTP method, the
	// returned status code SHOULD be used when writing the response.
	//
	// If handling errors after calling another ServeHTTP method, the
	// returned error value SHOULD be logged or handled accordingly.
	//
	// Otherwise, return values should be propagated down the middleware
	// chain by returning them unchanged.
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
//
// All paths passed into and returned from this function use '/' as the
// path separator, just like URLs.  IndexFle handles path manipulation
// internally for systems that use different path separators.
func IndexFile(root http.FileSystem, fpath string, indexFiles []string) (string, bool) {
	if fpath[len(fpath)-1] != '/' || root == nil {
		return "", false
	}
	for _, indexFile := range indexFiles {
		// func (http.FileSystem).Open wants all paths separated by "/",
		// regardless of operating system convention, so use
		// path.Join instead of filepath.Join
		fp := path.Join(fpath, indexFile)
		f, err := root.Open(fp)
		if err == nil {
			f.Close()
			return fp, true
		}
	}
	return "", false
}

// SetLastModifiedHeader checks if the provided modTime is valid and if it is sets it
// as a Last-Modified header to the ResponseWriter. If the modTime is in the future
// the current time is used instead.
func SetLastModifiedHeader(w http.ResponseWriter, modTime time.Time) {
	if modTime.IsZero() || modTime.Equal(time.Unix(0, 0)) {
		// the time does not appear to be valid. Don't put it in the response
		return
	}

	// RFC 2616 - Section 14.29 - Last-Modified:
	// An origin server MUST NOT send a Last-Modified date which is later than the
	// server's time of message origination. In such cases, where the resource's last
	// modification would indicate some time in the future, the server MUST replace
	// that date with the message origination date.
	now := currentTime()
	if modTime.After(now) {
		modTime = now
	}

	w.Header().Set("Last-Modified", modTime.UTC().Format(http.TimeFormat))
}

// currentTime, as it is defined here, returns time.Now().
// It's defined as a variable for mocking time in tests.
var currentTime = func() time.Time {
	return time.Now()
}
