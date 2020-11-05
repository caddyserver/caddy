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

package acmeserver

import (
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/caddyserver/caddy/v2"
	"github.com/caddyserver/caddy/v2/modules/caddyhttp"
	"github.com/caddyserver/caddy/v2/modules/caddypki"
	"github.com/go-chi/chi"
	"github.com/smallstep/certificates/acme"
	acmeAPI "github.com/smallstep/certificates/acme/api"
	"github.com/smallstep/certificates/authority"
	"github.com/smallstep/certificates/authority/provisioner"
	"github.com/smallstep/certificates/db"
	"github.com/smallstep/nosql"
)

func init() {
	caddy.RegisterModule(Handler{})
}

// Handler is an ACME server handler.
type Handler struct {
	// The ID of the CA to use for signing. This refers to
	// the ID given to the CA in the `pki` app. If omitted,
	// the default ID is "local".
	CA string `json:"ca,omitempty"`

	// The hostname or IP address by which ACME clients
	// will access the server. This is used to populate
	// the ACME directory endpoint. Default: localhost.
	// COMPATIBILITY NOTE / TODO: This property may go away in the
	// future, as it is currently only required due to
	// limitations in the underlying library. Do not rely
	// on this property long-term; check release notes.
	Host string `json:"host,omitempty"`

	// The path prefix under which to serve all ACME
	// endpoints. All other requests will not be served
	// by this handler and will be passed through to
	// the next one. Default: "/acme/"
	// COMPATIBILITY NOTE / TODO: This property may go away in the
	// future, as it is currently only required due to
	// limitations in the underlying library. Do not rely
	// on this property long-term; check release notes.
	PathPrefix string `json:"path_prefix,omitempty"`

	// Whether to store using FileIO rather than MemoryMap
	// Default: false
	NoMemoryMap bool `json:"no_memory_map,omitempty"`

	// Whether to use BadgerV2 storage
	// Default: false
	UseBadgerV2 bool `json:"use_badger_v2,omitempty"`

	acmeEndpoints http.Handler
}

// CaddyModule returns the Caddy module information.
func (Handler) CaddyModule() caddy.ModuleInfo {
	return caddy.ModuleInfo{
		ID:  "http.handlers.acme_server",
		New: func() caddy.Module { return new(Handler) },
	}
}

// Provision sets up the ACME server handler.
func (ash *Handler) Provision(ctx caddy.Context) error {
	// set some defaults
	if ash.CA == "" {
		ash.CA = caddypki.DefaultCAID
	}
	if ash.Host == "" {
		ash.Host = defaultHost
	}
	if ash.PathPrefix == "" {
		ash.PathPrefix = defaultPathPrefix
	}

	// get a reference to the configured CA
	appModule, err := ctx.App("pki")
	if err != nil {
		return err
	}
	pkiApp := appModule.(*caddypki.PKI)
	ca, ok := pkiApp.CAs[ash.CA]
	if !ok {
		return fmt.Errorf("no certificate authority configured with id: %s", ash.CA)
	}

	dbFolder := filepath.Join(caddy.AppDataDir(), "acme_server", "db")

	// TODO: See https://github.com/smallstep/nosql/issues/7
	err = os.MkdirAll(dbFolder, 0755)
	if err != nil {
		return fmt.Errorf("making folder for ACME server database: %v", err)
	}

	// Use FileIO rather than MemoryMap if provided
	// See https://github.com/caddyserver/caddy/issues/3847
	badgerFileLoadingMode := "MemoryMap"
	if ash.NoMemoryMap {
		badgerFileLoadingMode = "FileIO"
	}

	// Use BadgerV2 rather than badger if provided
	// See https://github.com/caddyserver/caddy/issues/3847
	dbType := "badger"
	if ash.UseBadgerV2 {
		dbType = "badgerV2"
	}

	authorityConfig := caddypki.AuthorityConfig{
		AuthConfig: &authority.AuthConfig{
			Provisioners: provisioner.List{
				&provisioner.ACME{
					Name: ash.CA,
					Type: provisioner.TypeACME.String(),
					Claims: &provisioner.Claims{
						MinTLSDur:     &provisioner.Duration{Duration: 5 * time.Minute},
						MaxTLSDur:     &provisioner.Duration{Duration: 24 * time.Hour * 365},
						DefaultTLSDur: &provisioner.Duration{Duration: 12 * time.Hour},
					},
				},
			},
		},
		DB: &db.Config{
			Type:                  dbType,
			DataSource:            dbFolder,
			BadgerFileLoadingMode: badgerFileLoadingMode,
		},
	}

	auth, err := ca.NewAuthority(authorityConfig)
	if err != nil {
		return err
	}

	acmeAuth, err := acme.NewAuthority(
		auth.GetDatabase().(nosql.DB),     // stores all the server state
		ash.Host,                          // used for directory links; TODO: not needed
		strings.Trim(ash.PathPrefix, "/"), // used for directory links
		auth)                              // configures the signing authority
	if err != nil {
		return err
	}

	// create the router for the ACME endpoints
	acmeRouterHandler := acmeAPI.New(acmeAuth)
	r := chi.NewRouter()
	r.Route(ash.PathPrefix, func(r chi.Router) {
		acmeRouterHandler.Route(r)
	})
	ash.acmeEndpoints = r

	return nil
}

func (ash Handler) ServeHTTP(w http.ResponseWriter, r *http.Request, next caddyhttp.Handler) error {
	if strings.HasPrefix(r.URL.Path, ash.PathPrefix) {
		ash.acmeEndpoints.ServeHTTP(w, r)
		return nil
	}
	return next.ServeHTTP(w, r)
}

const (
	defaultHost       = "localhost"
	defaultPathPrefix = "/acme/"
)

// Interface guards
var (
	_ caddyhttp.MiddlewareHandler = (*Handler)(nil)
	_ caddy.Provisioner           = (*Handler)(nil)
)
