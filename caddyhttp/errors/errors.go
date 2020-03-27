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

// Package errors implements an HTTP error handling middleware.
package errors

import (
	"fmt"
	"io"
	"mime"
	"net/http"
	"os"
	"path/filepath"
	"runtime"
	"strings"

	"github.com/caddyserver/caddy"
	"github.com/caddyserver/caddy/caddyhttp/httpserver"
)

func init() {
	caddy.RegisterPlugin("errors", caddy.Plugin{
		ServerType: "http",
		Action:     setup,
	})
}

// ErrorHandler handles HTTP errors (and errors from other middleware).
type ErrorHandler struct {
	Next             httpserver.Handler
	GenericErrorPage string         // default error page filename
	ErrorPages       map[int]string // map of status code to filename
	Log              *httpserver.Logger
	Debug            bool // if true, errors are written out to client rather than to a log
}

func (h ErrorHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) (int, error) {
	defer h.recovery(w, r)

	status, err := h.Next.ServeHTTP(w, r)

	if err != nil {
		errMsg := fmt.Sprintf("[ERROR %d %s] %v", status, r.URL.Path, err)
		if h.Debug {
			// Write error to response instead of to log
			w.Header().Set("Content-Type", "text/plain; charset=utf-8")
			w.WriteHeader(status)
			fmt.Fprintln(w, errMsg)
			return 0, err // returning 0 signals that a response has been written
		}
		h.Log.Println(errMsg)
	}

	if status >= 400 {
		h.errorPage(w, r, status)
		return 0, err
	}

	return status, err
}

// errorPage serves a static error page to w according to the status
// code. If there is an error serving the error page, a plaintext error
// message is written instead, and the extra error is logged.
func (h ErrorHandler) errorPage(w http.ResponseWriter, r *http.Request, code int) {
	// See if an error page for this status code was specified
	if pagePath, ok := h.findErrorPage(code); ok {
		// Try to open it
		errorPage, err := os.Open(pagePath)
		if err != nil {
			// An additional error handling an error... <insert grumpy cat here>
			h.Log.Printf("[NOTICE %d %s] could not load error page: %v", code, r.URL.String(), err)
			httpserver.DefaultErrorFunc(w, r, code)
			return
		}
		defer errorPage.Close()
		// Get content type by extension
		contentType := mime.TypeByExtension(filepath.Ext(pagePath))
		if contentType == "" {
			contentType = "text/html; charset=utf-8"
		}
		// Copy the page body into the response
		w.Header().Set("Content-Type", contentType)
		w.WriteHeader(code)
		_, err = io.Copy(w, errorPage)

		if err != nil {
			// Epic fail... sigh.
			h.Log.Printf("[NOTICE %d %s] could not respond with %s: %v", code, r.URL.String(), pagePath, err)
			httpserver.DefaultErrorFunc(w, r, code)
		}

		return
	}

	// Default error response
	httpserver.DefaultErrorFunc(w, r, code)
}

func (h ErrorHandler) findErrorPage(code int) (string, bool) {
	if pagePath, ok := h.ErrorPages[code]; ok {
		return pagePath, true
	}

	if h.GenericErrorPage != "" {
		return h.GenericErrorPage, true
	}

	return "", false
}

func (h ErrorHandler) recovery(w http.ResponseWriter, r *http.Request) {
	rec := recover()
	if rec == nil {
		return
	}

	// Obtain source of panic
	// From: https://gist.github.com/swdunlop/9629168
	var name, file string // function name, file name
	var line int
	var pc [16]uintptr
	n := runtime.Callers(3, pc[:])
	for _, pc := range pc[:n] {
		fn := runtime.FuncForPC(pc)
		if fn == nil {
			continue
		}
		file, line = fn.FileLine(pc)
		name = fn.Name()
		if !strings.HasPrefix(name, "runtime.") {
			break
		}
	}

	// Trim file path
	delim := "/github.com/caddyserver/caddy/"
	pkgPathPos := strings.Index(file, delim)
	if pkgPathPos > -1 && len(file) > pkgPathPos+len(delim) {
		file = file[pkgPathPos+len(delim):]
	}

	panicMsg := fmt.Sprintf("[PANIC %s] %s:%d - %v", r.URL.String(), file, line, rec)
	if h.Debug {
		// Write error and stack trace to the response rather than to a log
		var stackBuf [4096]byte
		stack := stackBuf[:runtime.Stack(stackBuf[:], false)]
		httpserver.WriteTextResponse(w, http.StatusInternalServerError, fmt.Sprintf("%s\n\n%s", panicMsg, stack))
	} else {
		// Currently we don't use the function name, since file:line is more conventional
		h.Log.Printf(panicMsg)
		h.errorPage(w, r, http.StatusInternalServerError)
	}
}
