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
	"fmt"
	"net/http"
	"os"
	"path"
	"time"

	"github.com/mholt/caddy"
)

func init() {
	initCaseSettings()
}

type (
	// Middleware is the middle layer which represents the traditional
	// idea of middleware: it chains one Handler to the next by being
	// passed the next Handler in the chain.
	Middleware func(Handler) Handler

	// ListenerMiddleware is similar to the Middleware type, except it
	// chains one net.Listener to the next.
	ListenerMiddleware func(caddy.Listener) caddy.Listener

	// Handler is like http.Handler except ServeHTTP may return a status
	// code and/or error.
	//
	// If ServeHTTP writes the response header, it should return a status
	// code of 0. This signals to other handlers before it that the response
	// is already handled, and that they should not write to it also. Keep
	// in mind that writing to the response body writes the header, too.
	//
	// If ServeHTTP encounters an error, it should return the error value
	// so it can be logged by designated error-handling middleware.
	//
	// If writing a response after calling the next ServeHTTP method, the
	// returned status code SHOULD be used when writing the response.
	//
	// If handling errors after calling the next ServeHTTP method, the
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

	// RequestMatcher checks to see if current request should be handled
	// by underlying handler.
	RequestMatcher interface {
		Match(r *http.Request) bool
	}

	// HandlerConfig is a middleware configuration.
	// This makes it possible for middlewares to have a common
	// configuration interface.
	//
	// TODO The long term plan is to get all middleware implement this
	// interface for configurations.
	HandlerConfig interface {
		RequestMatcher
		BasePath() string
	}

	// ConfigSelector selects a configuration.
	ConfigSelector []HandlerConfig
)

// ServeHTTP implements the Handler interface.
func (f HandlerFunc) ServeHTTP(w http.ResponseWriter, r *http.Request) (int, error) {
	return f(w, r)
}

// Select selects a Config.
// This chooses the config with the longest length.
func (c ConfigSelector) Select(r *http.Request) (config HandlerConfig) {
	for i := range c {
		if !c[i].Match(r) {
			continue
		}
		if config == nil || len(c[i].BasePath()) > len(config.BasePath()) {
			config = c[i]
		}
	}
	return config
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

// CaseSensitivePath determines if paths should be case sensitive.
// This is configurable via CASE_SENSITIVE_PATH environment variable.
var CaseSensitivePath = false

const caseSensitivePathEnv = "CASE_SENSITIVE_PATH"

// initCaseSettings loads case sensitivity config from environment variable.
//
// This could have been in init, but init cannot be called from tests.
func initCaseSettings() {
	switch os.Getenv(caseSensitivePathEnv) {
	case "1", "true":
		CaseSensitivePath = true
	default:
		CaseSensitivePath = false
	}
}

// MergeRequestMatchers merges multiple RequestMatchers into one.
// This allows a middleware to use multiple RequestMatchers.
func MergeRequestMatchers(matchers ...RequestMatcher) RequestMatcher {
	return requestMatchers(matchers)
}

type requestMatchers []RequestMatcher

// Match satisfies RequestMatcher interface.
func (m requestMatchers) Match(r *http.Request) bool {
	for _, matcher := range m {
		if !matcher.Match(r) {
			return false
		}
	}
	return true
}

// currentTime, as it is defined here, returns time.Now().
// It's defined as a variable for mocking time in tests.
var currentTime = func() time.Time { return time.Now() }

// EmptyNext is a no-op function that can be passed into
// Middleware functions so that the assignment to the
// Next field of the Handler can be tested.
//
// Used primarily for testing but needs to be exported so
// plugins can use this as a convenience.
var EmptyNext = HandlerFunc(func(w http.ResponseWriter, r *http.Request) (int, error) { return 0, nil })

// SameNext does a pointer comparison between next1 and next2.
//
// Used primarily for testing but needs to be exported so
// plugins can use this as a convenience.
func SameNext(next1, next2 Handler) bool {
	return fmt.Sprintf("%v", next1) == fmt.Sprintf("%v", next2)
}

// Context key constants.
const (
	// ReplacerCtxKey is the context key for a per-request replacer.
	ReplacerCtxKey caddy.CtxKey = "replacer"

	// RemoteUserCtxKey is the key for the remote user of the request, if any (basicauth).
	RemoteUserCtxKey caddy.CtxKey = "remote_user"

	// MitmCtxKey is the key for the result of MITM detection
	MitmCtxKey caddy.CtxKey = "mitm"

	// RequestIDCtxKey is the key for the U4 UUID value
	RequestIDCtxKey caddy.CtxKey = "request_id"
)
