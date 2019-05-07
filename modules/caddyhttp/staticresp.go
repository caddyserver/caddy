package caddyhttp

import (
	"fmt"
	"net/http"

	"bitbucket.org/lightcodelabs/caddy2"
)

func init() {
	caddy2.RegisterModule(caddy2.Module{
		Name: "http.responders.static",
		New:  func() (interface{}, error) { return new(Static), nil },
	})
}

// Static implements a simple responder for static responses.
// It is Caddy's default responder. TODO: Or is it?
type Static struct {
	StatusCode int         `json:"status_code"`
	Headers    http.Header `json:"headers"`
	Body       string      `json:"body"`
	Close      bool        `json:"close"`
}

func (s Static) ServeHTTP(w http.ResponseWriter, r *http.Request) error {
	repl := r.Context().Value(ReplacerCtxKey).(*Replacer)

	// close the connection
	r.Close = s.Close

	// set all headers, with replacements
	for field, vals := range s.Headers {
		field = repl.Replace(field, "")
		for i := range vals {
			vals[i] = repl.Replace(vals[i], "")
		}
		w.Header()[field] = vals
	}

	// write the headers with a status code
	statusCode := s.StatusCode
	if statusCode == 0 {
		statusCode = http.StatusOK
	}
	w.WriteHeader(statusCode)

	// write the response body, with replacements
	if s.Body != "" {
		fmt.Fprint(w, repl.Replace(s.Body, ""))
	}

	return nil
}

// Interface guard
var _ Handler = (*Static)(nil)
