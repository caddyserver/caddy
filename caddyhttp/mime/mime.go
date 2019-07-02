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

package mime

import (
	"net/http"
	"path"

	"github.com/caddyserver/caddy/caddyhttp/httpserver"
)

// Config represent a mime config. Map from extension to mime-type.
// Note, this should be safe with concurrent read access, as this is
// not modified concurrently.
type Config map[string]string

// Mime sets Content-Type header of requests based on configurations.
type Mime struct {
	Next    httpserver.Handler
	Configs Config
}

// ServeHTTP implements the httpserver.Handler interface.
func (e Mime) ServeHTTP(w http.ResponseWriter, r *http.Request) (int, error) {
	// Get a clean /-path, grab the extension
	ext := path.Ext(path.Clean(r.URL.Path))

	if contentType, ok := e.Configs[ext]; ok {
		w.Header().Set("Content-Type", contentType)
	}

	return e.Next.ServeHTTP(w, r)
}
