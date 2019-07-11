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
)

func init() {
	caddy.RegisterModule(caddy.Module{
		Name: "http.handlers.static_response",
		New:  func() interface{} { return new(StaticResponse) },
	})
}

// StaticResponse implements a simple responder for static responses.
type StaticResponse struct {
	StatusCode weakString  `json:"status_code"`
	Headers    http.Header `json:"headers"`
	Body       string      `json:"body"`
	Close      bool        `json:"close"`
}

func (s StaticResponse) ServeHTTP(w http.ResponseWriter, r *http.Request, _ Handler) error {
	repl := r.Context().Value(caddy.ReplacerCtxKey).(caddy.Replacer)

	// close the connection after responding
	r.Close = s.Close

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

	// get the status code
	statusCode := http.StatusOK
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
		fmt.Fprint(w, repl.ReplaceAll(s.Body, ""))
	}

	return nil
}

// Interface guard
var _ MiddlewareHandler = (*StaticResponse)(nil)
