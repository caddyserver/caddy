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
	"errors"
	"net/http"

	"go.uber.org/zap"

	"github.com/caddyserver/caddy/v2"
	"github.com/caddyserver/caddy/v2/internal/placeholder"
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
	_, single, fieldErr := placeholder.ParseSingle(h.Value)
	needsEarly := h.Early
	needsResponseBody := false
	if single && fieldErr == nil {
		var names []string
		names, fieldErr = placeholder.Names(h.Value)
		for _, name := range names {
			switch name {
			case placeholderRequestBody, placeholderRequestBodyBase64:
				needsEarly = true
			case placeholderResponseBody, placeholderResponseBodyBase64:
				needsResponseBody = true
			}
		}
	}

	var selected any
	selectedSet := false
	fieldAdded := false
	if needsEarly && fieldErr == nil {
		// Resolve only the selected branch before downstream handlers consume
		// the request body. Response-body branches wait until the response is
		// available; any request-body fallback then sees its current contents.
		selected, fieldErr = h.resolveLogValue(r, responseBodyProvider(nil, needsResponseBody))
		if fieldErr == nil && !isResponseBodyPending(selected) {
			selectedSet = true
			fieldErr = h.appendLogValue(r, selected)
			fieldAdded = fieldErr == nil
		}
	}
	if needsEarly && fieldErr != nil {
		return fieldErr
	}

	var rec caddyhttp.ResponseRecorder
	var buf *bytes.Buffer
	if needsResponseBody && !fieldAdded && fieldErr == nil {
		buf = new(bytes.Buffer)
		rec = caddyhttp.NewResponseRecorder(w, buf, func(status int, _ http.Header) bool {
			if status >= 100 && status <= 199 && status != http.StatusSwitchingProtocols {
				return false
			}
			// Select the branch when final response headers are written. A
			// non-body result is frozen at this point: streaming it prevents
			// a later change from selecting a body we did not capture.
			selected, fieldErr = h.resolveLogValue(r, responseBodyProvider(nil, true))
			selectedSet = fieldErr == nil && !isResponseBodyPending(selected)
			return fieldErr == nil && isResponseBodyPending(selected)
		})
		w = rec
	}

	handlerErr := next.ServeHTTP(w, r)
	if !fieldAdded && fieldErr == nil {
		if !selectedSet {
			// This also handles downstream handlers which never wrote a
			// response: the body is empty, so its default can be selected.
			selected, fieldErr = h.resolveLogValue(r, responseBodyProvider(buf, false))
		}
		if fieldErr == nil {
			fieldErr = h.appendLogValue(r, selected)
		}
	}
	// A late request-body fallback can carry a 413 while the response is
	// still buffered. Leave that response uncommitted so the error handler
	// can render the selected error's status instead of a success status.
	if handlerErr == nil && fieldErr != nil && rec != nil && rec.Buffered() {
		return fieldErr
	}
	var writeErr error
	if rec != nil && rec.Status() != 0 && rec.Buffered() {
		writeErr = rec.WriteResponse()
	}
	if handlerErr != nil {
		return handlerErr
	}
	if writeErr != nil {
		return writeErr
	}
	return fieldErr
}

func (h LogAppend) resolveLogValue(r *http.Request, override caddy.ReplacerFunc) (any, error) {
	_, single, err := placeholder.ParseSingle(h.Value)
	if err != nil {
		return nil, err
	}
	if single {
		repl := r.Context().Value(caddy.ReplacerCtxKey).(*caddy.Replacer)
		value, _, err := repl.ResolvePlaceholder(h.Value, override)
		return value, err
	}
	vars := r.Context().Value(caddyhttp.VarsCtxKey).(map[string]any)
	if value, ok := vars[h.Value]; ok {
		return value, nil
	}
	return h.Value, nil
}

func (h LogAppend) appendLogValue(r *http.Request, value any) error {
	// A selected body-limit error is control flow, not a printable log value.
	if err, ok := value.(error); ok {
		if bodyLimit, ok := errors.AsType[caddyhttp.RequestBodyLimitError](err); ok {
			return caddyhttp.HandlerError{Err: bodyLimit, StatusCode: bodyLimit.StatusCode()}
		}
	}
	extra := r.Context().Value(caddyhttp.ExtraLogFieldsCtxKey).(*caddyhttp.ExtraLogFields)
	extra.Add(zap.Any(h.Key, value))
	return nil
}

// responseBodyProvider provides handler-local values without mutating the
// request replacer. An error sentinel keeps selected composite defaults from
// stringifying the unavailable body during the buffering decision.
func responseBodyProvider(buf *bytes.Buffer, probe bool) caddy.ReplacerFunc {
	return func(key string) (any, bool) {
		switch key {
		case placeholderResponseBody, placeholderResponseBodyBase64:
			if probe {
				return errResponseBodyPending, true
			}
			if buf == nil {
				return "", true
			}
			if key == placeholderResponseBodyBase64 {
				return base64.StdEncoding.EncodeToString(buf.Bytes()), true
			}
			return buf.String(), true
		default:
			return nil, false
		}
	}
}

func isResponseBodyPending(value any) bool {
	err, ok := value.(error)
	return ok && errors.Is(err, errResponseBodyPending)
}

var errResponseBodyPending = errors.New("response body is not available yet")

const (
	// Provider keys whose lifetime needs special handling by log_append.
	placeholderRequestBody        = "http.request.body"
	placeholderRequestBodyBase64  = "http.request.body_base64"
	placeholderResponseBody       = "http.response.body"
	placeholderResponseBodyBase64 = "http.response.body_base64"
)

// Interface guards
var (
	_ caddyhttp.MiddlewareHandler = (*LogAppend)(nil)
)
