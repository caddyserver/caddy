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
	"errors"
	"fmt"
	weakrand "math/rand"
	"path"
	"runtime"
	"strings"

	"github.com/caddyserver/caddy/v2"
)

// Error is a convenient way for a Handler to populate the
// essential fields of a HandlerError. If err is itself a
// HandlerError, then any essential fields that are not
// set will be populated.
func Error(statusCode int, err error) HandlerError {
	const idLen = 9
	var he HandlerError
	if errors.As(err, &he) {
		if he.ID == "" {
			he.ID = randString(idLen, true)
		}
		if he.Trace == "" {
			he.Trace = trace()
		}
		if he.StatusCode == 0 {
			he.StatusCode = statusCode
		}
		return he
	}
	return HandlerError{
		ID:         randString(idLen, true),
		StatusCode: statusCode,
		Err:        err,
		Trace:      trace(),
	}
}

// HandlerError is a serializable representation of
// an error from within an HTTP handler.
type HandlerError struct {
	Err        error // the original error value and message
	StatusCode int   // the HTTP status code to associate with this error

	ID    string // generated; for identifying this error in logs
	Trace string // produced from call stack
}

func (e HandlerError) Error() string {
	var s string
	if e.ID != "" {
		s += fmt.Sprintf("{id=%s}", e.ID)
	}
	if e.Trace != "" {
		s += " " + e.Trace
	}
	if e.StatusCode != 0 {
		s += fmt.Sprintf(": HTTP %d", e.StatusCode)
	}
	if e.Err != nil {
		s += ": " + e.Err.Error()
	}
	return strings.TrimSpace(s)
}

// Unwrap returns the underlying error value. See the `errors` package for info.
func (e HandlerError) Unwrap() error { return e.Err }

// randString returns a string of n random characters.
// It is not even remotely secure OR a proper distribution.
// But it's good enough for some things. It excludes certain
// confusing characters like I, l, 1, 0, O, etc. If sameCase
// is true, then uppercase letters are excluded.
func randString(n int, sameCase bool) string {
	if n <= 0 {
		return ""
	}
	dict := []byte("abcdefghijkmnopqrstuvwxyzABCDEFGHJKLMNPQRTUVWXY23456789")
	if sameCase {
		dict = []byte("abcdefghijkmnpqrstuvwxyz0123456789")
	}
	b := make([]byte, n)
	for i := range b {
		//nolint:gosec
		b[i] = dict[weakrand.Int63()%int64(len(dict))]
	}
	return string(b)
}

func trace() string {
	if pc, file, line, ok := runtime.Caller(2); ok {
		filename := path.Base(file)
		pkgAndFuncName := path.Base(runtime.FuncForPC(pc).Name())
		return fmt.Sprintf("%s (%s:%d)", pkgAndFuncName, filename, line)
	}
	return ""
}

// ErrorCtxKey is the context key to use when storing
// an error (for use with context.Context).
const ErrorCtxKey = caddy.CtxKey("handler_chain_error")
