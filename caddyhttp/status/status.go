// Copyright 2015 Light Code Labs, LLC
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

// Package status is middleware for returning status code for requests
package status

import (
	"net/http"

	"github.com/caddyserver/caddy/caddyhttp/httpserver"
)

// Rule describes status rewriting rule
type Rule struct {
	// Base path. Request to this path and sub-paths will be answered with StatusCode
	Base string

	// Status code to return
	StatusCode int

	// Request matcher
	httpserver.RequestMatcher
}

// NewRule creates new Rule.
func NewRule(basePath string, status int) *Rule {
	return &Rule{
		Base:           basePath,
		StatusCode:     status,
		RequestMatcher: httpserver.PathMatcher(basePath),
	}
}

// BasePath implements httpserver.HandlerConfig interface
func (rule *Rule) BasePath() string {
	return rule.Base
}

// Status is a middleware to return status code for request
type Status struct {
	Rules []httpserver.HandlerConfig
	Next  httpserver.Handler
}

// ServeHTTP implements the httpserver.Handler interface
func (status Status) ServeHTTP(w http.ResponseWriter, r *http.Request) (int, error) {
	if cfg := httpserver.ConfigSelector(status.Rules).Select(r); cfg != nil {
		rule := cfg.(*Rule)

		if rule.StatusCode < 400 {
			// There's no ability to return response body --
			// write the response status code in header and signal
			// to other handlers that response is already handled
			w.WriteHeader(rule.StatusCode)
			return 0, nil
		}

		return rule.StatusCode, nil
	}

	return status.Next.ServeHTTP(w, r)
}
