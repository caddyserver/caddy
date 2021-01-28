// Copyright 2015 Matthew Holt and The Caddy Authors
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

package caddyhttp

import (
	"fmt"
	"net/http"
	"strconv"

	"github.com/caddyserver/caddy/v2"
	"github.com/caddyserver/caddy/v2/caddyconfig/caddyfile"
)

func init() {
	caddy.RegisterModule(StaticResponse{})
}

// StaticResponse implements a simple responder for static responses.
type StaticResponse struct {
	// The HTTP status code to respond with. Can be an integer or,
	// if needing to use a placeholder, a string.
	StatusCode WeakString `json:"status_code,omitempty"`

	// Header fields to set on the response.
	Headers http.Header `json:"headers,omitempty"`

	// The response body.
	Body string `json:"body,omitempty"`

	// If true, the server will close the client's connection
	// after writing the response.
	Close bool `json:"close,omitempty"`

	// Immediately and forcefully closes the connection without
	// writing a response. Interrupts any other HTTP streams on
	// the same connection.
	Abort bool `json:"abort,omitempty"`
}

// CaddyModule returns the Caddy module information.
func (StaticResponse) CaddyModule() caddy.ModuleInfo {
	return caddy.ModuleInfo{
		ID:  "http.handlers.static_response",
		New: func() caddy.Module { return new(StaticResponse) },
	}
}

// UnmarshalCaddyfile sets up the handler from Caddyfile tokens. Syntax:
//
//     respond [<matcher>] <status>|<body> [<status>] {
//         body <text>
//         close
//     }
//
// If there is just one argument (other than the matcher), it is considered
// to be a status code if it's a valid positive integer of 3 digits.
func (s *StaticResponse) UnmarshalCaddyfile(d *caddyfile.Dispenser) error {
	for d.Next() {
		args := d.RemainingArgs()
		switch len(args) {
		case 1:
			if len(args[0]) == 3 {
				if num, err := strconv.Atoi(args[0]); err == nil && num > 0 {
					s.StatusCode = WeakString(args[0])
					break
				}
			}
			s.Body = args[0]
		case 2:
			s.Body = args[0]
			s.StatusCode = WeakString(args[1])
		default:
			return d.ArgErr()
		}

		for d.NextBlock(0) {
			switch d.Val() {
			case "body":
				if s.Body != "" {
					return d.Err("body already specified")
				}
				if !d.AllArgs(&s.Body) {
					return d.ArgErr()
				}
			case "close":
				if s.Close {
					return d.Err("close already specified")
				}
				s.Close = true
			}
		}
	}
	return nil
}

func (s StaticResponse) ServeHTTP(w http.ResponseWriter, r *http.Request, _ Handler) error {
	// close the connection immediately
	if s.Abort {
		panic(http.ErrAbortHandler)
	}

	// close the connection after responding
	if s.Close {
		r.Close = true
		w.Header().Set("Connection", "close")
	}

	repl := r.Context().Value(caddy.ReplacerCtxKey).(*caddy.Replacer)

	// set all headers
	for field, vals := range s.Headers {
		field = repl.ReplaceAll(field, "")
		newVals := make([]string, len(vals))
		for i := range vals {
			newVals[i] = repl.ReplaceAll(vals[i], "")
		}
		w.Header()[field] = newVals
	}

	// do not allow Go to sniff the content-type
	if w.Header().Get("Content-Type") == "" {
		w.Header()["Content-Type"] = nil
	}

	// get the status code; if this handler exists in an error route,
	// use the recommended status code as the default; otherwise 200
	statusCode := http.StatusOK
	if reqErr, ok := r.Context().Value(ErrorCtxKey).(error); ok {
		if handlerErr, ok := reqErr.(HandlerError); ok {
			if handlerErr.StatusCode > 0 {
				statusCode = handlerErr.StatusCode
			}
		}
	}
	if codeStr := s.StatusCode.String(); codeStr != "" {
		intVal, err := strconv.Atoi(repl.ReplaceAll(codeStr, ""))
		if err != nil {
			return Error(http.StatusInternalServerError, err)
		}
		statusCode = intVal
	}

	// write headers
	w.WriteHeader(statusCode)

	// write response body
	if s.Body != "" {
		fmt.Fprint(w, repl.ReplaceKnown(s.Body, ""))
	}

	return nil
}

// Interface guards
var (
	_ MiddlewareHandler     = (*StaticResponse)(nil)
	_ caddyfile.Unmarshaler = (*StaticResponse)(nil)
)
