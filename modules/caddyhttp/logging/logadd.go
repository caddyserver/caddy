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
}

// CaddyModule returns the Caddy module information.
func (LogAppend) CaddyModule() caddy.ModuleInfo {
	return caddy.ModuleInfo{
		ID:  "http.handlers.log_append",
		New: func() caddy.Module { return new(LogAppend) },
	}
}

func (h LogAppend) ServeHTTP(w http.ResponseWriter, r *http.Request, next caddyhttp.Handler) error {
	// Run the next handler in the chain first.
	// If an error occurs, we still want to add
	// any extra log fields that we can, so we
	// hold onto the error and return it later.
	handlerErr := next.ServeHTTP(w, r)

	// On the way back up the chain, add the extra log field
	ctx := r.Context()

	vars := ctx.Value(caddyhttp.VarsCtxKey).(map[string]any)
	repl := ctx.Value(caddy.ReplacerCtxKey).(*caddy.Replacer)
	extra := ctx.Value(caddyhttp.ExtraLogFieldsCtxKey).(*caddyhttp.ExtraLogFields)

	var varValue any
	if strings.HasPrefix(h.Value, "{") &&
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

	return handlerErr
}

// Interface guards
var (
	_ caddyhttp.MiddlewareHandler = (*LogAppend)(nil)
)
