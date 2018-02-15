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
	"flag"
	"fmt"
	"log"
	"net"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/mholt/caddy"
	"github.com/mholt/caddy/caddyfile"
	"github.com/mholt/caddy/caddyhttp/staticfiles"
	"github.com/mholt/caddy/caddytls"
)

const serverType = "http"

func init() {
	flag.StringVar(&HTTPPort, "http-port", HTTPPort, "Default port to use for HTTP")
	flag.StringVar(&HTTPSPort, "https-port", HTTPSPort, "Default port to use for HTTPS")
	flag.StringVar(&Host, "host", DefaultHost, "Default host")
	flag.StringVar(&Port, "port", DefaultPort, "Default port")
	flag.StringVar(&Root, "root", DefaultRoot, "Root path of default site")
	flag.DurationVar(&GracefulTimeout, "grace", 5*time.Second, "Maximum duration of graceful shutdown")
	flag.BoolVar(&HTTP2, "http2", true, "Use HTTP/2")
	flag.BoolVar(&QUIC, "quic", false, "Use experimental QUIC")

	caddy.RegisterServerType(serverType, caddy.ServerType{
		Directives: func() []string { return directives },
		DefaultInput: func() caddy.Input {
			if Port == DefaultPort && Host != "" {
				// by leaving the port blank in this case we give auto HTTPS
				// a chance to set the port to 443 for us
				return caddy.CaddyfileInput{
					Contents:       []byte(fmt.Sprintf("%s\nroot %s", Host, Root)),
					ServerTypeName: serverType,
				}
			}
			return caddy.CaddyfileInput{
				Contents:       []byte(fmt.Sprintf("%s:%s\nroot %s", Host, Port, Root)),
				ServerTypeName: serverType,
			}
		},
		NewContext: newContext,
	})
	caddy.RegisterCaddyfileLoader("short", caddy.LoaderFunc(shortCaddyfileLoader))
	caddy.RegisterParsingCallback(serverType, "root", hideCaddyfile)
	caddy.RegisterParsingCallback(serverType, "tls", activateHTTPS)
	caddytls.RegisterConfigGetter(serverType, func(c *caddy.Controller) *caddytls.Config { return GetConfig(c).TLS })
}

// hideCaddyfile hides the source/origin Caddyfile if it is within the
// site root. This function should be run after parsing the root directive.
func hideCaddyfile(cctx caddy.Context) error {
	ctx := cctx.(*httpContext)
	for _, cfg := range ctx.siteConfigs {
		// if no Caddyfile exists exit.
		if cfg.originCaddyfile == "" {
			return nil
		}
		absRoot, err := filepath.Abs(cfg.Root)
		if err != nil {
			return err
		}
		absOriginCaddyfile, err := filepath.Abs(cfg.originCaddyfile)
		if err != nil {
			return err
		}
		if strings.HasPrefix(absOriginCaddyfile, absRoot) {
			cfg.HiddenFiles = append(cfg.HiddenFiles, filepath.ToSlash(strings.TrimPrefix(absOriginCaddyfile, absRoot)))
		}
	}
	return nil
}

func newContext(inst *caddy.Instance) caddy.Context {
	return &httpContext{instance: inst, keysToSiteConfigs: make(map[string]*SiteConfig)}
}

type httpContext struct {
	instance *caddy.Instance

	// keysToSiteConfigs maps an address at the top of a
	// server block (a "key") to its SiteConfig. Not all
	// SiteConfigs will be represented here, only ones
	// that appeared in the Caddyfile.
	keysToSiteConfigs map[string]*SiteConfig

	// siteConfigs is the master list of all site configs.
	siteConfigs []*SiteConfig
}

func (h *httpContext) saveConfig(key string, cfg *SiteConfig) {
	h.siteConfigs = append(h.siteConfigs, cfg)
	h.keysToSiteConfigs[key] = cfg
}

// InspectServerBlocks make sure that everything checks out before
// executing directives and otherwise prepares the directives to
// be parsed and executed.
func (h *httpContext) InspectServerBlocks(sourceFile string, serverBlocks []caddyfile.ServerBlock) ([]caddyfile.ServerBlock, error) {
	siteAddrs := make(map[string]string)

	// For each address in each server block, make a new config
	for _, sb := range serverBlocks {
		for _, key := range sb.Keys {
			key = strings.ToLower(key)
			if _, dup := h.keysToSiteConfigs[key]; dup {
				return serverBlocks, fmt.Errorf("duplicate site key: %s", key)
			}
			addr, err := standardizeAddress(key)
			if err != nil {
				return serverBlocks, err
			}

			// Fill in address components from command line so that middleware
			// have access to the correct information during setup
			if addr.Host == "" && Host != DefaultHost {
				addr.Host = Host
			}
			if addr.Port == "" && Port != DefaultPort {
				addr.Port = Port
			}

			// Make sure the adjusted site address is distinct
			addrCopy := addr // make copy so we don't disturb the original, carefully-parsed address struct
			if addrCopy.Port == "" && Port == DefaultPort {
				addrCopy.Port = Port
			}
			addrStr := strings.ToLower(addrCopy.String())
			if otherSiteKey, dup := siteAddrs[addrStr]; dup {
				err := fmt.Errorf("duplicate site address: %s", addrStr)
				if (addrCopy.Host == Host && Host != DefaultHost) ||
					(addrCopy.Port == Port && Port != DefaultPort) {
					err = fmt.Errorf("site defined as %s is a duplicate of %s because of modified "+
						"default host and/or port values (usually via -host or -port flags)", key, otherSiteKey)
				}
				return serverBlocks, err
			}
			siteAddrs[addrStr] = key

			// If default HTTP or HTTPS ports have been customized,
			// make sure the ACME challenge ports match
			var altHTTPPort, altTLSSNIPort string
			if HTTPPort != DefaultHTTPPort {
				altHTTPPort = HTTPPort
			}
			if HTTPSPort != DefaultHTTPSPort {
				altTLSSNIPort = HTTPSPort
			}

			// Make our caddytls.Config, which has a pointer to the
			// instance's certificate cache and enough information
			// to use automatic HTTPS when the time comes
			caddytlsConfig := caddytls.NewConfig(h.instance)
			caddytlsConfig.Hostname = addr.Host
			caddytlsConfig.AltHTTPPort = altHTTPPort
			caddytlsConfig.AltTLSSNIPort = altTLSSNIPort

			// Save the config to our master list, and key it for lookups
			cfg := &SiteConfig{
				Addr:            addr,
				Root:            Root,
				TLS:             caddytlsConfig,
				originCaddyfile: sourceFile,
				IndexPages:      staticfiles.DefaultIndexPages,
			}
			h.saveConfig(key, cfg)
		}
	}

	// For sites that have gzip (which gets chained in
	// before the error handler) we should ensure that the
	// errors directive also appears so error pages aren't
	// written after the gzip writer is closed. See #616.
	for _, sb := range serverBlocks {
		_, hasGzip := sb.Tokens["gzip"]
		_, hasErrors := sb.Tokens["errors"]
		if hasGzip && !hasErrors {
			sb.Tokens["errors"] = []caddyfile.Token{{Text: "errors"}}
		}
	}

	return serverBlocks, nil
}

// MakeServers uses the newly-created siteConfigs to
// create and return a list of server instances.
func (h *httpContext) MakeServers() ([]caddy.Server, error) {
	// make sure TLS is disabled for explicitly-HTTP sites
	// (necessary when HTTP address shares a block containing tls)
	for _, cfg := range h.siteConfigs {
		if !cfg.TLS.Enabled {
			continue
		}
		if cfg.Addr.Port == HTTPPort || cfg.Addr.Scheme == "http" {
			cfg.TLS.Enabled = false
			log.Printf("[WARNING] TLS disabled for %s", cfg.Addr)
		} else if cfg.Addr.Scheme == "" {
			// set scheme to https ourselves, since TLS is enabled
			// and it was not explicitly set to something else. this
			// makes it appear as "https" when we print the list of
			// running sites; otherwise "http" would be assumed which
			// is incorrect for this site.
			cfg.Addr.Scheme = "https"
		}
		if cfg.Addr.Port == "" && ((!cfg.TLS.Manual && !cfg.TLS.SelfSigned) || cfg.TLS.OnDemand) {
			// this is vital, otherwise the function call below that
			// sets the listener address will use the default port
			// instead of 443 because it doesn't know about TLS.
			cfg.Addr.Port = HTTPSPort
		}
	}

	// we must map (group) each config to a bind address
	groups, err := groupSiteConfigsByListenAddr(h.siteConfigs)
	if err != nil {
		return nil, err
	}

	// then we create a server for each group
	var servers []caddy.Server
	for addr, group := range groups {
		s, err := NewServer(addr, group)
		if err != nil {
			return nil, err
		}
		servers = append(servers, s)
	}

	return servers, nil
}

// GetConfig gets the SiteConfig that corresponds to c.
// If none exist (should only happen in tests), then a
// new, empty one will be created.
func GetConfig(c *caddy.Controller) *SiteConfig {
	ctx := c.Context().(*httpContext)
	key := strings.ToLower(c.Key)
	if cfg, ok := ctx.keysToSiteConfigs[key]; ok {
		return cfg
	}
	// we should only get here during tests because directive
	// actions typically skip the server blocks where we make
	// the configs
	cfg := &SiteConfig{Root: Root, TLS: new(caddytls.Config), IndexPages: staticfiles.DefaultIndexPages}
	ctx.saveConfig(key, cfg)
	return cfg
}

// shortCaddyfileLoader loads a Caddyfile if positional arguments are
// detected, or, in other words, if un-named arguments are provided to
// the program. A "short Caddyfile" is one in which each argument
// is a line of the Caddyfile. The default host and port are prepended
// according to the Host and Port values.
func shortCaddyfileLoader(serverType string) (caddy.Input, error) {
	if flag.NArg() > 0 && serverType == "http" {
		confBody := fmt.Sprintf("%s:%s\n%s", Host, Port, strings.Join(flag.Args(), "\n"))
		return caddy.CaddyfileInput{
			Contents:       []byte(confBody),
			Filepath:       "args",
			ServerTypeName: serverType,
		}, nil
	}
	return nil, nil
}

// groupSiteConfigsByListenAddr groups site configs by their listen
// (bind) address, so sites that use the same listener can be served
// on the same server instance. The return value maps the listen
// address (what you pass into net.Listen) to the list of site configs.
// This function does NOT vet the configs to ensure they are compatible.
func groupSiteConfigsByListenAddr(configs []*SiteConfig) (map[string][]*SiteConfig, error) {
	groups := make(map[string][]*SiteConfig)

	for _, conf := range configs {
		// We would add a special case here so that localhost addresses
		// bind to 127.0.0.1 if conf.ListenHost is not already set, which
		// would prevent outsiders from even connecting; but that was problematic:
		// https://caddy.community/t/wildcard-virtual-domains-with-wildcard-roots/221/5?u=matt

		if conf.Addr.Port == "" {
			conf.Addr.Port = Port
		}
		addr, err := net.ResolveTCPAddr("tcp", net.JoinHostPort(conf.ListenHost, conf.Addr.Port))
		if err != nil {
			return nil, err
		}
		addrstr := addr.String()
		groups[addrstr] = append(groups[addrstr], conf)
	}

	return groups, nil
}

// Address represents a site address. It contains
// the original input value, and the component
// parts of an address. The component parts may be
// updated to the correct values as setup proceeds,
// but the original value should never be changed.
type Address struct {
	Original, Scheme, Host, Port, Path string
}

// String returns a human-friendly print of the address.
func (a Address) String() string {
	if a.Host == "" && a.Port == "" {
		return ""
	}
	scheme := a.Scheme
	if scheme == "" {
		if a.Port == HTTPSPort {
			scheme = "https"
		} else {
			scheme = "http"
		}
	}
	s := scheme
	if s != "" {
		s += "://"
	}
	s += a.Host
	if a.Port != "" &&
		((scheme == "https" && a.Port != DefaultHTTPSPort) ||
			(scheme == "http" && a.Port != DefaultHTTPPort)) {
		s += ":" + a.Port
	}
	if a.Path != "" {
		s += a.Path
	}
	return s
}

// VHost returns a sensible concatenation of Host:Port/Path from a.
// It's basically the a.Original but without the scheme.
func (a Address) VHost() string {
	if idx := strings.Index(a.Original, "://"); idx > -1 {
		return a.Original[idx+3:]
	}
	return a.Original
}

// standardizeAddress parses an address string into a structured format with separate
// scheme, host, port, and path portions, as well as the original input string.
func standardizeAddress(str string) (Address, error) {
	input := str

	// Split input into components (prepend with // to assert host by default)
	if !strings.Contains(str, "//") && !strings.HasPrefix(str, "/") {
		str = "//" + str
	}
	u, err := url.Parse(str)
	if err != nil {
		return Address{}, err
	}

	// separate host and port
	host, port, err := net.SplitHostPort(u.Host)
	if err != nil {
		host, port, err = net.SplitHostPort(u.Host + ":")
		if err != nil {
			host = u.Host
		}
	}

	// see if we can set port based off scheme
	if port == "" {
		if u.Scheme == "http" {
			port = HTTPPort
		} else if u.Scheme == "https" {
			port = HTTPSPort
		}
	}

	// repeated or conflicting scheme is confusing, so error
	if u.Scheme != "" && (port == "http" || port == "https") {
		return Address{}, fmt.Errorf("[%s] scheme specified twice in address", input)
	}

	// error if scheme and port combination violate convention
	if (u.Scheme == "http" && port == HTTPSPort) || (u.Scheme == "https" && port == HTTPPort) {
		return Address{}, fmt.Errorf("[%s] scheme and port violate convention", input)
	}

	// standardize http and https ports to their respective port numbers
	if port == "http" {
		u.Scheme = "http"
		port = HTTPPort
	} else if port == "https" {
		u.Scheme = "https"
		port = HTTPSPort
	}

	return Address{Original: input, Scheme: u.Scheme, Host: host, Port: port, Path: u.Path}, err
}

// RegisterDevDirective splices name into the list of directives
// immediately before another directive. This function is ONLY
// for plugin development purposes! NEVER use it for a plugin
// that you are not currently building. If before is empty,
// the directive will be appended to the end of the list.
//
// It is imperative that directives execute in the proper
// order, and hard-coding the list of directives guarantees
// a correct, absolute order every time. This function is
// convenient when developing a plugin, but it does not
// guarantee absolute ordering. Multiple plugins registering
// directives with this function will lead to non-
// deterministic builds and buggy software.
//
// Directive names must be lower-cased and unique. Any errors
// here are fatal, and even successful calls print a message
// to stdout as a reminder to use it only in development.
func RegisterDevDirective(name, before string) {
	if name == "" {
		fmt.Println("[FATAL] Cannot register empty directive name")
		os.Exit(1)
	}
	if strings.ToLower(name) != name {
		fmt.Printf("[FATAL] %s: directive name must be lowercase\n", name)
		os.Exit(1)
	}
	for _, dir := range directives {
		if dir == name {
			fmt.Printf("[FATAL] %s: directive name already exists\n", name)
			os.Exit(1)
		}
	}
	if before == "" {
		directives = append(directives, name)
	} else {
		var found bool
		for i, dir := range directives {
			if dir == before {
				directives = append(directives[:i], append([]string{name}, directives[i:]...)...)
				found = true
				break
			}
		}
		if !found {
			fmt.Printf("[FATAL] %s: directive not found\n", before)
			os.Exit(1)
		}
	}
	msg := fmt.Sprintf("Registered directive '%s' ", name)
	if before == "" {
		msg += "at end of list"
	} else {
		msg += fmt.Sprintf("before '%s'", before)
	}
	fmt.Printf("[DEV NOTICE] %s\n", msg)
}

// directives is the list of all directives known to exist for the
// http server type, including non-standard (3rd-party) directives.
// The ordering of this list is important.
var directives = []string{
	// primitive actions that set up the fundamental vitals of each config
	"root",
	"index",
	"bind",
	"limits",
	"timeouts",
	"tls",

	// services/utilities, or other directives that don't necessarily inject handlers
	"startup",  // TODO: Deprecate this directive
	"shutdown", // TODO: Deprecate this directive
	"on",
	"request_id",
	"realip", // github.com/captncraig/caddy-realip
	"git",    // github.com/abiosoft/caddy-git

	// directives that add listener middleware to the stack
	"proxyprotocol", // github.com/mastercactapus/caddy-proxyprotocol

	// directives that add middleware to the stack
	"locale", // github.com/simia-tech/caddy-locale
	"log",
	"cache", // github.com/nicolasazrak/caddy-cache
	"rewrite",
	"ext",
	"gzip",
	"header",
	"errors",
	"authz",        // github.com/casbin/caddy-authz
	"filter",       // github.com/echocat/caddy-filter
	"minify",       // github.com/hacdias/caddy-minify
	"ipfilter",     // github.com/pyed/ipfilter
	"ratelimit",    // github.com/xuqingfeng/caddy-rate-limit
	"search",       // github.com/pedronasser/caddy-search
	"expires",      // github.com/epicagency/caddy-expires
	"forwardproxy", // github.com/caddyserver/forwardproxy
	"basicauth",
	"redir",
	"status",
	"cors",   // github.com/captncraig/cors/caddy
	"nobots", // github.com/Xumeiquer/nobots
	"mime",
	"login",     // github.com/tarent/loginsrv/caddy
	"reauth",    // github.com/freman/caddy-reauth
	"jwt",       // github.com/BTBurke/caddy-jwt
	"jsonp",     // github.com/pschlump/caddy-jsonp
	"upload",    // blitznote.com/src/caddy.upload
	"multipass", // github.com/namsral/multipass/caddy
	"internal",
	"pprof",
	"expvar",
	"push",
	"datadog",    // github.com/payintech/caddy-datadog
	"prometheus", // github.com/miekg/caddy-prometheus
	"templates",
	"proxy",
	"fastcgi",
	"cgi", // github.com/jung-kurt/caddy-cgi
	"websocket",
	"filemanager", // github.com/hacdias/filemanager/caddy/filemanager
	"webdav",      // github.com/hacdias/caddy-webdav
	"markdown",
	"browse",
	"jekyll",    // github.com/hacdias/filemanager/caddy/jekyll
	"hugo",      // github.com/hacdias/filemanager/caddy/hugo
	"mailout",   // github.com/SchumacherFM/mailout
	"awses",     // github.com/miquella/caddy-awses
	"awslambda", // github.com/coopernurse/caddy-awslambda
	"grpc",      // github.com/pieterlouw/caddy-grpc
	"gopkg",     // github.com/zikes/gopkg
	"restic",    // github.com/restic/caddy
}

const (
	// DefaultHost is the default host.
	DefaultHost = ""
	// DefaultPort is the default port.
	DefaultPort = "2015"
	// DefaultRoot is the default root folder.
	DefaultRoot = "."
	// DefaultHTTPPort is the default port for HTTP.
	DefaultHTTPPort = "80"
	// DefaultHTTPSPort is the default port for HTTPS.
	DefaultHTTPSPort = "443"
)

// These "soft defaults" are configurable by
// command line flags, etc.
var (
	// Root is the site root
	Root = DefaultRoot

	// Host is the site host
	Host = DefaultHost

	// Port is the site port
	Port = DefaultPort

	// GracefulTimeout is the maximum duration of a graceful shutdown.
	GracefulTimeout time.Duration

	// HTTP2 indicates whether HTTP2 is enabled or not.
	HTTP2 bool

	// QUIC indicates whether QUIC is enabled or not.
	QUIC bool

	// HTTPPort is the port to use for HTTP.
	HTTPPort = DefaultHTTPPort

	// HTTPSPort is the port to use for HTTPS.
	HTTPSPort = DefaultHTTPSPort
)
