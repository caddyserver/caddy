// Package errors implements an HTTP error handling middleware.
package errors

import (
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"runtime"
	"strings"
	"time"

	"github.com/mholt/caddy/middleware"
)

// ErrorHandler handles HTTP errors (or errors from other middleware).
type ErrorHandler struct {
	Next       middleware.Handler
	ErrorPages map[int]string // map of status code to filename
	LogFile    string
	Log        *log.Logger
}

func (h ErrorHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) (int, error) {
	defer h.recovery(w, r)

	status, err := h.Next.ServeHTTP(w, r)

	if err != nil {
		h.Log.Printf("%s [ERROR %d %s] %v", time.Now().Format(timeFormat), status, r.URL.Path, err)
	}

	if status >= 400 {
		h.errorPage(w, status)
		return 0, err // status < 400 signals that a response has been written
	}

	return status, err
}

// errorPage serves a static error page to w according to the status
// code. If there is an error serving the error page, a plaintext error
// message is written instead, and the extra error is logged.
func (h ErrorHandler) errorPage(w http.ResponseWriter, code int) {
	defaultBody := fmt.Sprintf("%d %s", code, http.StatusText(code))

	// See if an error page for this status code was specified
	if pagePath, ok := h.ErrorPages[code]; ok {

		// Try to open it
		errorPage, err := os.Open(pagePath)
		if err != nil {
			// An error handling an error... <insert grumpy cat here>
			h.Log.Printf("HTTP %d could not load error page %s: %v", code, pagePath, err)
			http.Error(w, defaultBody, code)
			return
		}
		defer errorPage.Close()

		// Copy the page body into the response
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		w.WriteHeader(code)
		_, err = io.Copy(w, errorPage)

		if err != nil {
			// Epic fail... sigh.
			h.Log.Printf("HTTP %d could not respond with %s: %v", code, pagePath, err)
			http.Error(w, defaultBody, code)
		}

		return
	}

	// Default error response
	http.Error(w, defaultBody, code)
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
	delim := "/caddy/"
	pkgPathPos := strings.Index(file, delim)
	if pkgPathPos > -1 && len(file) > pkgPathPos+len(delim) {
		file = file[pkgPathPos+len(delim):]
	}

	// Currently we don't use the function name, as file:line is more conventional
	h.Log.Printf("%s [PANIC %s] %s:%d - %v", time.Now().Format(timeFormat), r.URL.String(), file, line, rec)
	h.errorPage(w, http.StatusInternalServerError)
}

const DefaultLogFilename = "error.log"
const timeFormat = "02/Jan/2006:15:04:05 -0700"
