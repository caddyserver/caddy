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
	caddy.RegisterModule(StaticError{})
}

// StaticError implements a simple handler that returns an error.
// This handler returns an error value, but does not write a response.
// This is useful when you want the server to act as if an error
// occurred; for example, to invoke your custom error handling logic.
//
// Since this handler does not write a response, the error information
// is for use by the server to know how to handle the error.
type StaticError struct {
	// The error message. Optional. Default is no error message.
	Error string `json:"error,omitempty"`

	// The recommended HTTP status code. Can be either an integer or a
	// string if placeholders are needed. Optional. Default is 500.
	StatusCode WeakString `json:"status_code,omitempty"`
}

// CaddyModule returns the Caddy module information.
func (StaticError) CaddyModule() caddy.ModuleInfo {
	return caddy.ModuleInfo{
		ID:  "http.handlers.error",
		New: func() caddy.Module { return new(StaticError) },
	}
}

// UnmarshalCaddyfile sets up the handler from Caddyfile tokens. Syntax:
//
//	error [<matcher>] <status>|<message> [<status>] {
//	    message <text>
//	}
//
// If there is just one argument (other than the matcher), it is considered
// to be a status code if it's a valid positive integer of 3 digits.
func (e *StaticError) UnmarshalCaddyfile(d *caddyfile.Dispenser) error {
	d.Next() // consume directive name
	args := d.RemainingArgs()
	switch len(args) {
	case 1:
		if len(args[0]) == 3 {
			if num, err := strconv.Atoi(args[0]); err == nil && num > 0 {
				e.StatusCode = WeakString(args[0])
				break
			}
		}
		e.Error = args[0]
	case 2:
		e.Error = args[0]
		e.StatusCode = WeakString(args[1])
	default:
		return d.ArgErr()
	}

	for d.NextBlock(0) {
		switch d.Val() {
		case "message":
			if e.Error != "" {
				return d.Err("message already specified")
			}
			if !d.AllArgs(&e.Error) {
				return d.ArgErr()
			}
		default:
			return d.Errf("unrecognized subdirective '%s'", d.Val())
		}
	}
	return nil
}

func (e StaticError) ServeHTTP(w http.ResponseWriter, r *http.Request, _ Handler) error {
	repl := r.Context().Value(caddy.ReplacerCtxKey).(*caddy.Replacer)

	statusCode := http.StatusInternalServerError
	if codeStr := e.StatusCode.String(); codeStr != "" {
		intVal, err := strconv.Atoi(repl.ReplaceAll(codeStr, ""))
		if err != nil {
			return Error(http.StatusInternalServerError, err)
		}
		statusCode = intVal
	}
	return Error(statusCode, fmt.Errorf("%s", repl.ReplaceKnown(e.Error, "")))
}

// Interface guard
var (
	_ MiddlewareHandler     = (*StaticError)(nil)
	_ caddyfile.Unmarshaler = (*StaticError)(nil)
)
