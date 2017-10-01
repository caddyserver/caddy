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

package rewrite

import (
	"log"
	"net/http"
	"net/url"
	"path"
	"strings"

	"github.com/mholt/caddy/caddyhttp/httpserver"
)

// To attempts rewrite. It attempts to rewrite to first valid path
// or the last path if none of the paths are valid.
func To(fs http.FileSystem, r *http.Request, to string, replacer httpserver.Replacer) Result {
	tos := strings.Fields(to)

	// try each rewrite paths
	t := ""
	query := ""
	for _, v := range tos {
		t = replacer.Replace(v)
		tparts := strings.SplitN(t, "?", 2)
		t = path.Clean(tparts[0])

		if len(tparts) > 1 {
			query = tparts[1]
		}

		// add trailing slash for directories, if present
		if strings.HasSuffix(tparts[0], "/") && !strings.HasSuffix(t, "/") {
			t += "/"
		}

		// validate file
		if validFile(fs, t) {
			break
		}
	}

	// validate resulting path
	u, err := url.Parse(t)
	if err != nil {
		// Let the user know we got here. Rewrite is expected but
		// the resulting url is invalid.
		log.Printf("[ERROR] rewrite: resulting path '%v' is invalid. error: %v", t, err)
		return RewriteIgnored
	}

	// perform rewrite
	r.URL.Path = u.Path
	if query != "" {
		// overwrite query string if present
		r.URL.RawQuery = query
	}
	if u.Fragment != "" {
		// overwrite fragment if present
		r.URL.Fragment = u.Fragment
	}

	return RewriteDone
}

// validFile checks if file exists on the filesystem.
// if file ends with `/`, it is validated as a directory.
func validFile(fs http.FileSystem, file string) bool {
	if fs == nil {
		return false
	}

	f, err := fs.Open(file)
	if err != nil {
		return false
	}
	defer f.Close()

	stat, err := f.Stat()
	if err != nil {
		return false
	}

	// directory
	if strings.HasSuffix(file, "/") {
		return stat.IsDir()
	}

	// file
	return !stat.IsDir()
}
