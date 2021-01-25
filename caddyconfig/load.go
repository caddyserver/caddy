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

package caddyconfig

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"mime"
	"net/http"
	"strings"
	"sync"

	"github.com/caddyserver/caddy/v2"
)

func init() {
	caddy.RegisterModule(adminLoad{})
}

// adminLoad is a module that provides the /load endpoint
// for the Caddy admin API. The only reason it's not baked
// into the caddy package directly is because of the import
// of the caddyconfig package for its GetAdapter function.
// If the caddy package depends on the caddyconfig package,
// then the caddyconfig package will not be able to import
// the caddy package, and it can more easily cause backward
// edges in the dependency tree (i.e. import cycle).
// Fortunately, the admin API has first-class support for
// adding endpoints from modules.
type adminLoad struct{}

// CaddyModule returns the Caddy module information.
func (adminLoad) CaddyModule() caddy.ModuleInfo {
	return caddy.ModuleInfo{
		ID:  "admin.api.load",
		New: func() caddy.Module { return new(adminLoad) },
	}
}

// Routes returns a route for the /load endpoint.
func (al adminLoad) Routes() []caddy.AdminRoute {
	return []caddy.AdminRoute{
		{
			Pattern: "/load",
			Handler: caddy.AdminHandlerFunc(al.handleLoad),
		},
	}
}

// handleLoad replaces the entire current configuration with
// a new one provided in the response body. It supports config
// adapters through the use of the Content-Type header. A
// config that is identical to the currently-running config
// will be a no-op unless Cache-Control: must-revalidate is set.
func (adminLoad) handleLoad(w http.ResponseWriter, r *http.Request) error {
	if r.Method != http.MethodPost {
		return caddy.APIError{
			HTTPStatus: http.StatusMethodNotAllowed,
			Err:        fmt.Errorf("method not allowed"),
		}
	}

	buf := bufPool.Get().(*bytes.Buffer)
	buf.Reset()
	defer bufPool.Put(buf)

	_, err := io.Copy(buf, r.Body)
	if err != nil {
		return caddy.APIError{
			HTTPStatus: http.StatusBadRequest,
			Err:        fmt.Errorf("reading request body: %v", err),
		}
	}
	body := buf.Bytes()

	// if the config is formatted other than Caddy's native
	// JSON, we need to adapt it before loading it
	if ctHeader := r.Header.Get("Content-Type"); ctHeader != "" {
		ct, _, err := mime.ParseMediaType(ctHeader)
		if err != nil {
			return caddy.APIError{
				HTTPStatus: http.StatusBadRequest,
				Err:        fmt.Errorf("invalid Content-Type: %v", err),
			}
		}
		if !strings.HasSuffix(ct, "/json") {
			slashIdx := strings.Index(ct, "/")
			if slashIdx < 0 {
				return caddy.APIError{
					HTTPStatus: http.StatusBadRequest,
					Err:        fmt.Errorf("malformed Content-Type"),
				}
			}
			adapterName := ct[slashIdx+1:]
			cfgAdapter := GetAdapter(adapterName)
			if cfgAdapter == nil {
				return caddy.APIError{
					HTTPStatus: http.StatusBadRequest,
					Err:        fmt.Errorf("unrecognized config adapter '%s'", adapterName),
				}
			}
			result, warnings, err := cfgAdapter.Adapt(body, nil)
			if err != nil {
				return caddy.APIError{
					HTTPStatus: http.StatusBadRequest,
					Err:        fmt.Errorf("adapting config using %s adapter: %v", adapterName, err),
				}
			}
			if len(warnings) > 0 {
				respBody, err := json.Marshal(warnings)
				if err != nil {
					caddy.Log().Named("admin.api.load").Error(err.Error())
				}
				_, _ = w.Write(respBody)
			}
			body = result
		}
	}

	forceReload := r.Header.Get("Cache-Control") == "must-revalidate"

	err = caddy.Load(body, forceReload)
	if err != nil {
		return caddy.APIError{
			HTTPStatus: http.StatusBadRequest,
			Err:        fmt.Errorf("loading config: %v", err),
		}
	}

	caddy.Log().Named("admin.api").Info("load complete")

	return nil
}

var bufPool = sync.Pool{
	New: func() interface{} {
		return new(bytes.Buffer)
	},
}
