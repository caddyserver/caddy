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

package httpserver

import (
	"net/http"
	"path"
	"strings"
)

// Path represents a URI path. It should usually be
// set to the value of a request path.
type Path string

// Matches checks to see if base matches p. The correct
// usage of this method sets p as the request path, and
// base as a Caddyfile (user-defined) rule path.
//
// Path matching will probably not always be a direct
// comparison; this method assures that paths can be
// easily and consistently matched.
//
// Multiple slashes are collapsed/merged. See issue #1859.
func (p Path) Matches(base string) bool {
	if base == "/" || base == "" {
		return true
	}

	// sanitize the paths for comparison, very important
	// (slightly lossy if the base path requires multiple
	// consecutive forward slashes, since those will be merged)
	pHasTrailingSlash := strings.HasSuffix(string(p), "/")
	baseHasTrailingSlash := strings.HasSuffix(base, "/")
	p = Path(path.Clean(string(p)))
	base = path.Clean(base)
	if pHasTrailingSlash {
		p += "/"
	}
	if baseHasTrailingSlash {
		base += "/"
	}

	if CaseSensitivePath {
		return strings.HasPrefix(string(p), base)
	}
	return strings.HasPrefix(strings.ToLower(string(p)), strings.ToLower(base))
}

// PathMatcher is a Path RequestMatcher.
type PathMatcher string

// Match satisfies RequestMatcher.
func (p PathMatcher) Match(r *http.Request) bool {
	return Path(r.URL.Path).Matches(string(p))
}
