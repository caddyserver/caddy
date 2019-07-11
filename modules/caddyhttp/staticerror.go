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
	"strings"

	"github.com/caddyserver/caddy/v2"
)

func init() {
	caddy.RegisterModule(caddy.Module{
		Name: "http.handlers.error",
		New:  func() interface{} { return new(StaticError) },
	})
}

// StaticError implements a simple handler that returns an error.
type StaticError struct {
	Error      string     `json:"error,omitempty"`
	StatusCode weakString `json:"status_code,omitempty"`
}

func (e StaticError) ServeHTTP(w http.ResponseWriter, r *http.Request, _ Handler) error {
	repl := r.Context().Value(caddy.ReplacerCtxKey).(caddy.Replacer)

	statusCode := http.StatusInternalServerError
	if codeStr := e.StatusCode.String(); codeStr != "" {
		intVal, err := strconv.Atoi(repl.ReplaceAll(codeStr, ""))
		if err != nil {
			return Error(http.StatusInternalServerError, err)
		}
		statusCode = intVal
	}

	return Error(statusCode, fmt.Errorf("%s", e.Error))
}

// Interface guard
var _ MiddlewareHandler = (*StaticError)(nil)

// weakString is a type that unmarshals any JSON value
// as a string literal, and provides methods for
// getting the value as different primitive types.
// However, using this type removes any type safety
// as far as deserializing JSON is concerned.
type weakString string

// UnmarshalJSON satisfies json.Unmarshaler. It
// unmarshals b by always interpreting it as a
// string literal.
func (ws *weakString) UnmarshalJSON(b []byte) error {
	*ws = weakString(strings.Trim(string(b), `"`))
	return nil
}

// Int returns ws as an integer. If ws is not an
// integer, 0 is returned.
func (ws weakString) Int() int {
	num, _ := strconv.Atoi(string(ws))
	return num
}

// Float64 returns ws as a float64. If ws is not a
// float value, the zero value is returned.
func (ws weakString) Float64() float64 {
	num, _ := strconv.ParseFloat(string(ws), 64)
	return num
}

// Bool returns ws as a boolean. If ws is not a
// boolean, false is returned.
func (ws weakString) Bool() bool {
	return string(ws) == "true"
}

// String returns ws as a string.
func (ws weakString) String() string {
	return string(ws)
}
