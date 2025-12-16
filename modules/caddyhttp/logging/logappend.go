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

package logging

import (
	"bytes"
	"encoding/base64"
	"net/http"
	"strings"

	"go.uber.org/zap"

	"github.com/caddyserver/caddy/v2"
	"github.com/caddyserver/caddy/v2/modules/caddyhttp"
)

func init() {
	caddy.RegisterModule(LogAppend{})
}

// LogAppend implements a middleware that takes a key and value, where
// the key is the name of a log field and the value is a placeholder,
// or variable key, or constant value to use for that field.
type LogAppend struct {
	// Key is the name of the log field.
	Key string `json:"key,omitempty"`

	// Value is the value to use for the log field.
	// If it is a placeholder (with surrounding `{}`),
	// it will be evaluated when the log is written.
	// If the value is a key that exists in the `vars`
	// map, the value of that key will be used. Otherwise
	// the value will be used as-is as a constant string.
	Value string `json:"value,omitempty"`

	// Early, if true, adds the log field before calling
	// the next handler in the chain. By default, the log
	// field is added on the way back up the middleware chain,
	// after all subsequent handlers have completed.
	Early bool `json:"early,omitempty"`
}

// CaddyModule returns the Caddy module information.
func (LogAppend) CaddyModule() caddy.ModuleInfo {
	return caddy.ModuleInfo{
		ID:  "http.handlers.log_append",
		New: func() caddy.Module { return new(LogAppend) },
	}
}

func (h LogAppend) ServeHTTP(w http.ResponseWriter, r *http.Request, next caddyhttp.Handler) error {
	// Determine if we need to add the log field early.
	// We do if the Early flag is set, or for convenience,
	// if the value is a special placeholder for the request body.
	needsEarly := h.Early || h.Value == placeholderRequestBody || h.Value == placeholderRequestBodyBase64

	// Check if we need to buffer the response for special placeholders
	needsResponseBody := h.Value == placeholderResponseBody || h.Value == placeholderResponseBodyBase64

	if needsEarly && !needsResponseBody {
		// Add the log field before calling the next handler
		// (but not if we need the response body, which isn't available yet)
		h.addLogField(r, nil)
	}

	var rec caddyhttp.ResponseRecorder
	var buf *bytes.Buffer

	if needsResponseBody {
		// Wrap the response writer with a recorder to capture the response body
		buf = new(bytes.Buffer)
		rec = caddyhttp.NewResponseRecorder(w, buf, func(status int, header http.Header) bool {
			// Always buffer the response when we need to log the body
			return true
		})
		w = rec
	}

	// Run the next handler in the chain.
	// If an error occurs, we still want to add
	// any extra log fields that we can, so we
	// hold onto the error and return it later.
	handlerErr := next.ServeHTTP(w, r)

	if needsResponseBody {
		// Write the buffered response to the client
		if rec.Buffered() {
			h.addLogField(r, buf)
			err := rec.WriteResponse()
			if err != nil {
				return err
			}
		}
		return handlerErr
	}

	if !h.Early {
		// Add the log field after the handler completes
		h.addLogField(r, buf)
	}

	return handlerErr
}

// addLogField adds the log field to the request's extra log fields.
// If buf is not nil, it contains the buffered response body for special
// response body placeholders.
func (h LogAppend) addLogField(r *http.Request, buf *bytes.Buffer) {
	ctx := r.Context()

	vars := ctx.Value(caddyhttp.VarsCtxKey).(map[string]any)
	repl := ctx.Value(caddy.ReplacerCtxKey).(*caddy.Replacer)
	extra := ctx.Value(caddyhttp.ExtraLogFieldsCtxKey).(*caddyhttp.ExtraLogFields)

	var varValue any

	// Handle special case placeholders for response body
	if h.Value == placeholderResponseBody {
		if buf != nil {
			varValue = buf.String()
		} else {
			varValue = ""
		}
	} else if h.Value == placeholderResponseBodyBase64 {
		if buf != nil {
			varValue = base64.StdEncoding.EncodeToString(buf.Bytes())
		} else {
			varValue = ""
		}
	} else if strings.HasPrefix(h.Value, "{") &&
		strings.HasSuffix(h.Value, "}") &&
		strings.Count(h.Value, "{") == 1 {
		// the value looks like a placeholder, so get its value
		varValue, _ = repl.Get(strings.Trim(h.Value, "{}"))
	} else if val, ok := vars[h.Value]; ok {
		// the value is a key in the vars map
		varValue = val
	} else {
		// the value is a constant string
		varValue = h.Value
	}

	// Add the field to the extra log fields.
	// We use zap.Any because it will reflect
	// to the correct type for us.
	extra.Add(zap.Any(h.Key, varValue))
}

const (
	// Special placeholder values that are handled by log_append
	// rather than by the replacer.
	placeholderRequestBody        = "{http.request.body}"
	placeholderRequestBodyBase64  = "{http.request.body_base64}"
	placeholderResponseBody       = "{http.response.body}"
	placeholderResponseBodyBase64 = "{http.response.body_base64}"
)

// Interface guards
var (
	_ caddyhttp.MiddlewareHandler = (*LogAppend)(nil)
)
