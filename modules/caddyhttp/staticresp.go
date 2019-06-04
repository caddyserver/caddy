package caddyhttp

import (
	"fmt"
	"net/http"
	"strconv"

	"github.com/caddyserver/caddy2"
)

func init() {
	caddy2.RegisterModule(caddy2.Module{
		Name: "http.responders.static",
		New:  func() interface{} { return new(Static) },
	})
}

// Static implements a simple responder for static responses.
type Static struct {
	StatusCode    int         `json:"status_code"` // TODO: should we turn this into a string so that only one field is needed? (string allows replacements)
	StatusCodeStr string      `json:"status_code_str"`
	Headers       http.Header `json:"headers"`
	Body          string      `json:"body"`
	Close         bool        `json:"close"`
}

func (s Static) ServeHTTP(w http.ResponseWriter, r *http.Request) error {
	repl := r.Context().Value(caddy2.ReplacerCtxKey).(caddy2.Replacer)

	// close the connection after responding
	r.Close = s.Close

	// set all headers
	for field, vals := range s.Headers {
		field = repl.ReplaceAll(field, "")
		for i := range vals {
			vals[i] = repl.ReplaceAll(vals[i], "")
		}
		w.Header()[field] = vals
	}

	// get the status code
	statusCode := s.StatusCode
	if statusCode == 0 && s.StatusCodeStr != "" {
		intVal, err := strconv.Atoi(repl.ReplaceAll(s.StatusCodeStr, ""))
		if err == nil {
			statusCode = intVal
		}
	}
	if statusCode == 0 {
		statusCode = http.StatusOK
	}

	// write headers
	w.WriteHeader(statusCode)

	// write response body
	if s.Body != "" {
		fmt.Fprint(w, repl.ReplaceAll(s.Body, ""))
	}

	return nil
}

// Interface guard
var _ Handler = (*Static)(nil)
