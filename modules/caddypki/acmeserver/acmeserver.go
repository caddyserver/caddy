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
	"context"
	"fmt"
	weakrand "math/rand"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/smallstep/certificates/acme"
	"github.com/smallstep/certificates/acme/api"
	acmeNoSQL "github.com/smallstep/certificates/acme/db/nosql"
	"github.com/smallstep/certificates/authority"
	"github.com/smallstep/certificates/authority/provisioner"
	"github.com/smallstep/certificates/db"
	"github.com/smallstep/nosql"
	"go.uber.org/zap"
	"go.uber.org/zap/zapcore"

	"github.com/caddyserver/caddy/v2"
	"github.com/caddyserver/caddy/v2/modules/caddyhttp"
	"github.com/caddyserver/caddy/v2/modules/caddypki"
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

	// The lifetime for issued certificates
	Lifetime caddy.Duration `json:"lifetime,omitempty"`

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

	// The addresses of DNS resolvers to use when looking up
	// the TXT records for solving DNS challenges.
	// It accepts [network addresses](/docs/conventions#network-addresses)
	// with port range of only 1. If the host is an IP address,
	// it will be dialed directly to resolve the upstream server.
	// If the host is not an IP address, the addresses are resolved
	// using the [name resolution convention](https://golang.org/pkg/net/#hdr-Name_Resolution)
	// of the Go standard library. If the array contains more
	// than 1 resolver address, one is chosen at random.
	Resolvers []string `json:"resolvers,omitempty"`

	// Specify the set of enabled ACME challenges. An empty or absent value
	// means all challenges are enabled. Accepted values are:
	// "http-01", "dns-01", "tls-alpn-01"
	Challenges ACMEChallenges `json:"challenges,omitempty" `

	// The policy to use for issuing certificates
	Policy *Policy `json:"policy,omitempty"`

	logger    *zap.Logger
	resolvers []caddy.NetworkAddress
	ctx       caddy.Context

	acmeDB        acme.DB
	acmeAuth      *authority.Authority
	acmeClient    acme.Client
	acmeLinker    acme.Linker
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
	ash.ctx = ctx
	ash.logger = ctx.Logger()

	// set some defaults
	if ash.CA == "" {
		ash.CA = caddypki.DefaultCAID
	}
	if ash.PathPrefix == "" {
		ash.PathPrefix = defaultPathPrefix
	}
	if ash.Lifetime == 0 {
		ash.Lifetime = caddy.Duration(12 * time.Hour)
	}
	if len(ash.Challenges) > 0 {
		if err := ash.Challenges.validate(); err != nil {
			return err
		}
	}

	// get a reference to the configured CA
	appModule, err := ctx.App("pki")
	if err != nil {
		return err
	}
	pkiApp := appModule.(*caddypki.PKI)
	ca, err := pkiApp.GetCA(ctx, ash.CA)
	if err != nil {
		return err
	}

	// make sure leaf cert lifetime is less than the intermediate cert lifetime. this check only
	// applies for caddy-managed intermediate certificates
	if ca.Intermediate == nil && ash.Lifetime >= ca.IntermediateLifetime {
		return fmt.Errorf("certificate lifetime (%s) should be less than intermediate certificate lifetime (%s)", time.Duration(ash.Lifetime), time.Duration(ca.IntermediateLifetime))
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
					Name:       ash.CA,
					Challenges: ash.Challenges.toSmallstepType(),
					Options: &provisioner.Options{
						X509: ash.Policy.normalizeRules(),
					},
					Type: provisioner.TypeACME.String(),
					Claims: &provisioner.Claims{
						MinTLSDur:     &provisioner.Duration{Duration: 5 * time.Minute},
						MaxTLSDur:     &provisioner.Duration{Duration: 24 * time.Hour * 365},
						DefaultTLSDur: &provisioner.Duration{Duration: time.Duration(ash.Lifetime)},
					},
				},
			},
		},
		DB: database,
	}

	ash.acmeAuth, err = ca.NewAuthority(authorityConfig)
	if err != nil {
		return err
	}

	ash.acmeDB, err = acmeNoSQL.New(ash.acmeAuth.GetDatabase().(nosql.DB))
	if err != nil {
		return fmt.Errorf("configuring ACME DB: %v", err)
	}

	ash.acmeClient, err = ash.makeClient()
	if err != nil {
		return err
	}

	ash.acmeLinker = acme.NewLinker(
		ash.Host,
		strings.Trim(ash.PathPrefix, "/"),
	)

	// extract its http.Handler so we can use it directly
	r := chi.NewRouter()
	r.Route(ash.PathPrefix, func(r chi.Router) {
		api.Route(r)
	})
	ash.acmeEndpoints = r

	return nil
}

func (ash Handler) ServeHTTP(w http.ResponseWriter, r *http.Request, next caddyhttp.Handler) error {
	if strings.HasPrefix(r.URL.Path, ash.PathPrefix) {
		acmeCtx := acme.NewContext(
			r.Context(),
			ash.acmeDB,
			ash.acmeClient,
			ash.acmeLinker,
			nil,
		)
		acmeCtx = authority.NewContext(acmeCtx, ash.acmeAuth)
		r = r.WithContext(acmeCtx)

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
		if c := ash.logger.Check(zapcore.DebugLevel, "unloading unused CA database"); c != nil {
			c.Write(zap.String("db_key", key))
		}
	}
	if err != nil {
		if c := ash.logger.Check(zapcore.ErrorLevel, "closing CA database"); c != nil {
			c.Write(zap.String("db_key", key), zap.Error(err))
		}
	}
	return err
}

func (ash Handler) openDatabase() (*db.AuthDB, error) {
	key := ash.getDatabaseKey()
	database, loaded, err := databasePool.LoadOrNew(key, func() (caddy.Destructor, error) {
		dbFolder := filepath.Join(caddy.AppDataDir(), "acme_server", key)
		dbPath := filepath.Join(dbFolder, "db")

		err := os.MkdirAll(dbFolder, 0o755)
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
		if c := ash.logger.Check(zapcore.DebugLevel, "loaded preexisting CA database"); c != nil {
			c.Write(zap.String("db_key", key))
		}
	}

	return database.(databaseCloser).DB, err
}

// makeClient creates an ACME client which will use a custom
// resolver instead of net.DefaultResolver.
func (ash Handler) makeClient() (acme.Client, error) {
	for _, v := range ash.Resolvers {
		addr, err := caddy.ParseNetworkAddressWithDefaults(v, "udp", 53)
		if err != nil {
			return nil, err
		}
		if addr.PortRangeSize() != 1 {
			return nil, fmt.Errorf("resolver address must have exactly one address; cannot call %v", addr)
		}
		ash.resolvers = append(ash.resolvers, addr)
	}

	var resolver *net.Resolver
	if len(ash.resolvers) != 0 {
		dialer := &net.Dialer{
			Timeout: 2 * time.Second,
		}
		resolver = &net.Resolver{
			PreferGo: true,
			Dial: func(ctx context.Context, network, address string) (net.Conn, error) {
				//nolint:gosec
				addr := ash.resolvers[weakrand.Intn(len(ash.resolvers))]
				return dialer.DialContext(ctx, addr.Network, addr.JoinHostPort(0))
			},
		}
	} else {
		resolver = net.DefaultResolver
	}

	return resolverClient{
		Client:   acme.NewClient(),
		resolver: resolver,
		ctx:      ash.ctx,
	}, nil
}

type resolverClient struct {
	acme.Client

	resolver *net.Resolver
	ctx      context.Context
}

func (c resolverClient) LookupTxt(name string) ([]string, error) {
	return c.resolver.LookupTXT(c.ctx, name)
}

const defaultPathPrefix = "/acme/"

var (
	keyCleaner   = regexp.MustCompile(`[^\w.-_]`)
	databasePool = caddy.NewUsagePool()
)

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
