// Copyright 2019 Light Code Labs, LLC
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

package alias

import (
	"net/http"
	"path/filepath"
	"strings"

	"github.com/mholt/caddy/caddyhttp/httpserver"
	"github.com/mholt/caddy/caddyhttp/staticfiles"
)

// AliasHandler is a handler to which changes the root folder.
type AliasHandler struct {
	url     string
	handler httpserver.Handler

	Next httpserver.Handler
}

// NewAliasHandler creates a new AlaisHandler with the provided options.
func NewAliasHandler(url, path string, cfg *httpserver.SiteConfig, next httpserver.Handler) *AliasHandler {
	h := &AliasHandler{
		url: url,

		Next: next,
	}

	if path != "" {
		if !filepath.IsAbs(path) {
			path = filepath.Join(cfg.Root, path)
		}
		h.handler = &staticfiles.FileServer{
			Root:       http.Dir(path),
			Hide:       cfg.HiddenFiles,
			IndexPages: cfg.IndexPages,
		}
	}

	return h
}

func (h *AliasHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) (int, error) {
	if strings.HasPrefix(r.RequestURI, h.url) {
		r.URL.Path = strings.TrimPrefix(r.URL.Path, h.url)
		if r.URL.Opaque != "" {
			r.URL.Opaque = strings.TrimPrefix(r.URL.Opaque, h.url)
		}
		if r.URL.RawPath != "" {
			r.URL.RawPath = strings.TrimPrefix(r.URL.RawPath, h.url)
		}

		return h.handler.ServeHTTP(w, r)
	}

	return h.Next.ServeHTTP(w, r)
}
