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
	"net/http"
	"strconv"

	"github.com/caddyserver/caddy/v2"
	"github.com/caddyserver/caddy/v2/caddyconfig/caddyfile"
)

func init() {
	caddy.RegisterModule(StatusCode{})
}

// StaticResponse implements a simple responder for static responses.
type StatusCode struct {
	// The HTTP status code to respond with. Can be an integer or,
	// if needing to use a placeholder, a string.
	StatusCode WeakString `json:"status_code,omitempty"`
}

// CaddyModule returns the Caddy module information.
func (StatusCode) CaddyModule() caddy.ModuleInfo {
	return caddy.ModuleInfo{
		ID:  "http.handlers.status_code",
		New: func() caddy.Module { return new(StatusCode) },
	}
}

// UnmarshalCaddyfile sets up the handler from Caddyfile tokens. Syntax:
//
//     status_code [<matcher>] <status>
//
func (s *StatusCode) UnmarshalCaddyfile(d *caddyfile.Dispenser) error {
	for d.Next() {
		args := d.RemainingArgs()
		switch len(args) {
		case 1:
			s.StatusCode = WeakString(args[0])
		default:
			return d.ArgErr()
		}
	}
	return nil
}

func (s StatusCode) ServeHTTP(w http.ResponseWriter, r *http.Request, _ Handler) error {
	repl := r.Context().Value(caddy.ReplacerCtxKey).(*caddy.Replacer)

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

	return nil
}

// Interface guards
var (
	_ MiddlewareHandler     = (*StatusCode)(nil)
	_ caddyfile.Unmarshaler = (*StatusCode)(nil)
)
