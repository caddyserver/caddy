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

	"github.com/caddyserver/caddy/v2"
)

func init() {
	caddy.RegisterModule(caddy.Module{
		Name: "http.handlers.table",
		New:  func() interface{} { return new(tableMiddleware) },
	})

	caddy.RegisterModule(caddy.Module{
		Name: "http.matchers.table",
		New:  func() interface{} { return new(tableMatcher) },
	})
}

type tableMiddleware struct {
}

func (t tableMiddleware) ServeHTTP(w http.ResponseWriter, r *http.Request, next Handler) error {
	// tbl := r.Context().Value(TableCtxKey).(map[string]interface{})

	// TODO: implement this...

	return nil
}

type tableMatcher struct {
}

func (m tableMatcher) Match(r *http.Request) bool {
	return false // TODO: implement
}

// Interface guards
var _ MiddlewareHandler = (*tableMiddleware)(nil)
var _ RequestMatcher = (*tableMatcher)(nil)
