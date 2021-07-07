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
	"regexp"
	"strings"
	"time"

	"github.com/caddyserver/caddy/v2"
	"github.com/caddyserver/caddy/v2/modules/caddyhttp"
	"github.com/caddyserver/caddy/v2/modules/caddypki"
	"github.com/go-chi/chi"
	"github.com/smallstep/certificates/acme"
	acmeAPI "github.com/smallstep/certificates/acme/api"
	acmeNoSQL "github.com/smallstep/certificates/acme/db/nosql"
	"github.com/smallstep/certificates/authority"
	"github.com/smallstep/certificates/authority/provisioner"
	"github.com/smallstep/certificates/db"
	"github.com/smallstep/nosql"
	"go.uber.org/zap"
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
	// the ACME directory endpoint. If not set, the Host
	// header of the request will be used.
	// COMPATIBILITY NOTE / TODO: This property may go away in the
	// future. Do not rely on this property long-term; check release notes.
	Host string `json:"host,omitempty"`

	// The path prefix under which to serve all ACME
	// endpoints. All other requests will not be served
	// by this handler and will be passed through to
	// the next one. Default: "/acme/".
	// COMPATIBILITY NOTE / TODO: This property may go away in the
	// future, as it is currently only required due to
	// limitations in the underlying library. Do not rely
	// on this property long-term; check release notes.
	PathPrefix string `json:"path_prefix,omitempty"`

	// If true, the CA's root will be the issuer instead of
	// the intermediate. This is NOT recommended and should
	// only be used when devices/clients do not properly
	// validate certificate chains. EXPERIMENTAL: Might be
	// changed or removed in the future.
	SignWithRoot bool `json:"sign_with_root,omitempty"`

	acmeEndpoints http.Handler
	logger        *zap.Logger
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
	ash.logger = ctx.Logger(ash)
	// set some defaults
	if ash.CA == "" {
		ash.CA = caddypki.DefaultCAID
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

	database, err := ash.openDatabase()
	if err != nil {
		return err
	}

	authorityConfig := caddypki.AuthorityConfig{
		SignWithRoot: ash.SignWithRoot,
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
		DB: database,
	}

	auth, err := ca.NewAuthority(authorityConfig)
	if err != nil {
		return err
	}

	var acmeDB acme.DB
	if authorityConfig.DB != nil {
		acmeDB, err = acmeNoSQL.New(auth.GetDatabase().(nosql.DB))
		if err != nil {
			return fmt.Errorf("configuring ACME DB: %v", err)
		}
	}

	// create the router for the ACME endpoints
	acmeRouterHandler := acmeAPI.NewHandler(acmeAPI.HandlerOptions{
		CA:     auth,
		DB:     acmeDB,                            // stores all the server state
		DNS:    ash.Host,                          // used for directory links
		Prefix: strings.Trim(ash.PathPrefix, "/"), // used for directory links
	})

	// extract its http.Handler so we can use it directly
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

func (ash Handler) getDatabaseKey() string {
	key := ash.CA
	key = strings.ToLower(key)
	key = strings.TrimSpace(key)
	return keyCleaner.ReplaceAllLiteralString(key, "")
}

// Cleanup implements caddy.CleanerUpper and closes any idle databases.
func (ash Handler) Cleanup() error {
	key := ash.getDatabaseKey()
	deleted, err := databasePool.Delete(key)
	if deleted {
		ash.logger.Debug("unloading unused CA database", zap.String("db_key", key))
	}
	if err != nil {
		ash.logger.Error("closing CA database", zap.String("db_key", key), zap.Error(err))
	}
	return err
}

func (ash Handler) openDatabase() (*db.AuthDB, error) {
	key := ash.getDatabaseKey()
	database, loaded, err := databasePool.LoadOrNew(key, func() (caddy.Destructor, error) {
		dbFolder := filepath.Join(caddy.AppDataDir(), "acme_server", key)
		dbPath := filepath.Join(dbFolder, "db")

		err := os.MkdirAll(dbFolder, 0755)
		if err != nil {
			return nil, fmt.Errorf("making folder for CA database: %v", err)
		}

		dbConfig := &db.Config{
			Type:       "bbolt",
			DataSource: dbPath,
		}
		database, err := db.New(dbConfig)
		return databaseCloser{&database}, err
	})

	if loaded {
		ash.logger.Debug("loaded preexisting CA database", zap.String("db_key", key))
	}

	return database.(databaseCloser).DB, err
}

const defaultPathPrefix = "/acme/"

var keyCleaner = regexp.MustCompile(`[^\w.-_]`)
var databasePool = caddy.NewUsagePool()

type databaseCloser struct {
	DB *db.AuthDB
}

func (closer databaseCloser) Destruct() error {
	return (*closer.DB).Shutdown()
}

// Interface guards
var (
	_ caddyhttp.MiddlewareHandler = (*Handler)(nil)
	_ caddy.Provisioner           = (*Handler)(nil)
)
