// Package errors implements an HTTP error handling middleware.
package errors

import (
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"path"
	"strconv"

	"github.com/mholt/caddy/middleware"
)

// New instantiates a new instance of error-handling middleware.
func New(c middleware.Controller) (middleware.Middleware, error) {
	handler, err := parse(c)
	if err != nil {
		return nil, err
	}

	// Open the log file for writing when the server starts
	c.Startup(func() error {
		var err error
		var file *os.File

		if handler.LogFile == "stdout" {
			file = os.Stdout
		} else if handler.LogFile == "stderr" {
			file = os.Stderr
		} else if handler.LogFile != "" {
			file, err = os.OpenFile(handler.LogFile, os.O_RDWR|os.O_CREATE|os.O_APPEND, 0644)
			if err != nil {
				return err
			}
		}

		handler.Log = log.New(file, "", 0)
		return nil
	})

	return func(next middleware.Handler) middleware.Handler {
		handler.Next = next
		return handler
	}, nil
}

// ErrorHandler handles HTTP errors (or errors from other middleware).
type ErrorHandler struct {
	Next       middleware.Handler
	ErrorPages map[int]string // map of status code to filename
	LogFile    string
	Log        *log.Logger
}

func (h ErrorHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) (int, error) {
	defer func() {
		if rec := recover(); rec != nil {
			h.Log.Printf("[PANIC %s] %v", r.URL.String(), rec)
			h.errorPage(w, http.StatusInternalServerError)
		}
	}()

	status, err := h.Next.ServeHTTP(w, r)

	if err != nil {
		h.Log.Printf("[ERROR %d %s] %v", status, r.URL.Path, err)
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

func parse(c middleware.Controller) (*ErrorHandler, error) {
	// Very important that we make a pointer because the Startup
	// function that opens the log file must have access to the
	// same instance of the handler, not a copy.
	handler := &ErrorHandler{ErrorPages: make(map[int]string)}

	optionalBlock := func() (bool, error) {
		var hadBlock bool

		for c.NextBlock() {
			hadBlock = true

			what := c.Val()
			if !c.NextArg() {
				return hadBlock, c.ArgErr()
			}
			where := c.Val()

			if what == "log" {
				handler.LogFile = where
			} else {
				// Error page; ensure it exists
				where = path.Join(c.Root(), where)
				f, err := os.Open(where)
				if err != nil {
					return hadBlock, c.Err("Unable to open error page '" + where + "': " + err.Error())
				}
				f.Close()

				whatInt, err := strconv.Atoi(what)
				if err != nil {
					return hadBlock, c.Err("Expecting a numeric status code, got '" + what + "'")
				}
				handler.ErrorPages[whatInt] = where
			}
		}
		return hadBlock, nil
	}

	for c.Next() {
		// Configuration may be in a block
		hadBlock, err := optionalBlock()
		if err != nil {
			return handler, err
		}

		// Otherwise, the only argument would be an error log file name
		if !hadBlock {
			if c.NextArg() {
				handler.LogFile = c.Val()
			} else {
				handler.LogFile = defaultLogFilename
			}
		}
	}

	return handler, nil
}

const defaultLogFilename = "error.log"
