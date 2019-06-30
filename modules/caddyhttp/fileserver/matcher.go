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

package fileserver

import (
	"net/http"
	"os"

	"github.com/caddyserver/caddy"
	"github.com/caddyserver/caddy/modules/caddyhttp"
)

func init() {
	caddy.RegisterModule(caddy.Module{
		Name: "http.matchers.file",
		New:  func() interface{} { return new(FileMatcher) },
	})
}

// FileMatcher is a matcher that can match requests
// based on the local file system.
// TODO: Not sure how to do this well; we'd need the ability to
// hide files, etc...
// TODO: Also consider a feature to match directory that
// contains a certain filename (use filepath.Glob), useful
// if wanting to map directory-URI requests where the dir
// has index.php to PHP backends, for example (although this
// can effectively be done with rehandling already)
type FileMatcher struct {
	Root  string   `json:"root"`
	Path  string   `json:"path"`
	Flags []string `json:"flags"`
}

// Match matches the request r against m.
func (m FileMatcher) Match(r *http.Request) bool {
	fullPath := sanitizedPathJoin(m.Root, m.Path)
	var match bool
	if len(m.Flags) > 0 {
		match = true
		fi, err := os.Stat(fullPath)
		for _, f := range m.Flags {
			switch f {
			case "EXIST":
				match = match && os.IsNotExist(err)
			case "DIR":
				match = match && err == nil && fi.IsDir()
			default:
				match = false
			}
		}
	}
	return match
}

// Interface guard
var _ caddyhttp.RequestMatcher = (*FileMatcher)(nil)
