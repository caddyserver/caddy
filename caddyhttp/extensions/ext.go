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

// Package extensions contains middleware for clean URLs.
//
// The root path of the site is passed in as well as possible extensions
// to try internally for paths requested that don't match an existing
// resource. The first path+ext combination that matches a valid file
// will be used.
package extensions

import (
	"net/http"
	"os"
	"path"
	"strings"

	"github.com/caddyserver/caddy/caddyhttp/httpserver"
)

// Ext can assume an extension from clean URLs.
// It tries extensions in the order listed in Extensions.
type Ext struct {
	// Next handler in the chain
	Next httpserver.Handler

	// Path to site root
	Root string

	// List of extensions to try
	Extensions []string
}

// ServeHTTP implements the httpserver.Handler interface.
func (e Ext) ServeHTTP(w http.ResponseWriter, r *http.Request) (int, error) {
	urlpath := strings.TrimSuffix(r.URL.Path, "/")
	if len(r.URL.Path) > 0 && path.Ext(urlpath) == "" && r.URL.Path[len(r.URL.Path)-1] != '/' {
		for _, ext := range e.Extensions {
			_, err := os.Stat(httpserver.SafePath(e.Root, urlpath) + ext)
			if err == nil {
				r.URL.Path = urlpath + ext
				break
			}
		}
	}
	return e.Next.ServeHTTP(w, r)
}
