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
	"crypto/tls"
	"flag"
	"fmt"
	"log"
	"net"
	"net/url"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/caddyserver/caddy"
	"github.com/caddyserver/caddy/caddyfile"
	"github.com/caddyserver/caddy/caddyhttp/staticfiles"
	"github.com/caddyserver/caddy/caddytls"
	"github.com/caddyserver/caddy/telemetry"
	"github.com/mholt/certmagic"
)

const serverType = "http"

func init() {
	flag.IntVar(&certmagic.HTTPPort, "http-port", certmagic.HTTPPort, "Default port to use for HTTP")
	flag.IntVar(&certmagic.HTTPSPort, "https-port", certmagic.HTTPSPort, "Default port to use for HTTPS")
	flag.StringVar(&Host, "host", DefaultHost, "Default host")
	flag.StringVar(&Port, "port", DefaultPort, "Default port")
	flag.StringVar(&Root, "root", DefaultRoot, "Root path of default site")
	flag.DurationVar(&GracefulTimeout, "grace", 5*time.Second, "Maximum duration of graceful shutdown")
	flag.BoolVar(&HTTP2, "http2", true, "Use HTTP/2")
	flag.BoolVar(&QUIC, "quic", false, "Use experimental QUIC")

	caddy.RegisterServerType(serverType, caddy.ServerType{
		Directives: func() []string { return directives },
		DefaultInput: func() caddy.Input {
			if Port == DefaultHTTPSPort && serverType == "http" {
				fmt.Println("Port 443 can only be used for https sites.")
				os.Exit(1)
			}

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

	// disable the caddytls package reporting ClientHellos
	// to telemetry, since our MITM detector does this but
	// with more information than the standard lib provides
	// (as of May 2018)
	caddytls.ClientHelloTelemetry = false
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
	httpPort := strconv.Itoa(certmagic.HTTPPort)
	httpsPort := strconv.Itoa(certmagic.HTTPSPort)

	// For each address in each server block, make a new config
	for _, sb := range serverBlocks {
		for _, key := range sb.Keys {
			addr, err := standardizeAddress(key)
			if err != nil {
				return serverBlocks, err
			}

			addr = addr.Normalize()
			key = addr.Key()
			if _, dup := h.keysToSiteConfigs[key]; dup {
				return serverBlocks, fmt.Errorf("duplicate site key: %s", key)
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
			addrStr := addrCopy.String()
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
			var altHTTPPort, altTLSALPNPort int
			if httpPort != DefaultHTTPPort {
				portInt, err := strconv.Atoi(httpPort)
				if err != nil {
					return nil, err
				}
				altHTTPPort = portInt
			}
			if httpsPort != DefaultHTTPSPort {
				portInt, err := strconv.Atoi(httpsPort)
				if err != nil {
					return nil, err
				}
				altTLSALPNPort = portInt
			}

			// Make our caddytls.Config, which has a pointer to the
			// instance's certificate cache and enough information
			// to use automatic HTTPS when the time comes
			caddytlsConfig, err := caddytls.NewConfig(h.instance)
			if err != nil {
				return nil, fmt.Errorf("creating new caddytls configuration: %v", err)
			}
			caddytlsConfig.Hostname = addr.Host
			caddytlsConfig.Manager.AltHTTPPort = altHTTPPort
			caddytlsConfig.Manager.AltTLSALPNPort = altTLSALPNPort

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
	httpPort := strconv.Itoa(certmagic.HTTPPort)
	httpsPort := strconv.Itoa(certmagic.HTTPSPort)

	// make a rough estimate as to whether we're in a "production
	// environment/system" - start by assuming that most production
	// servers will set their default CA endpoint to a public,
	// trusted CA (obviously not a perfect heuristic)
	var looksLikeProductionCA bool
	for _, publicCAEndpoint := range caddytls.KnownACMECAs {
		if strings.Contains(certmagic.Default.CA, publicCAEndpoint) {
			looksLikeProductionCA = true
			break
		}
	}

	// Iterate each site configuration and make sure that:
	// 1) TLS is disabled for explicitly-HTTP sites (necessary
	//    when an HTTP address shares a block containing tls)
	// 2) if QUIC is enabled, TLS ClientAuth is not, because
	//    currently, QUIC does not support ClientAuth (TODO:
	//    revisit this when our QUIC implementation supports it)
	// 3) if TLS ClientAuth is used, StrictHostMatching is on
	var atLeastOneSiteLooksLikeProduction bool
	for _, cfg := range h.siteConfigs {
		// see if all the addresses (both sites and
		// listeners) are loopback to help us determine
		// if this is a "production" instance or not
		if !atLeastOneSiteLooksLikeProduction {
			if !caddy.IsLoopback(cfg.Addr.Host) &&
				!caddy.IsLoopback(cfg.ListenHost) &&
				(caddytls.QualifiesForManagedTLS(cfg) ||
					certmagic.HostQualifies(cfg.Addr.Host)) {
				atLeastOneSiteLooksLikeProduction = true
			}
		}

		// make sure TLS is disabled for explicitly-HTTP sites
		// (necessary when HTTP address shares a block containing tls)
		if !cfg.TLS.Enabled {
			continue
		}
		if cfg.Addr.Port == httpPort || cfg.Addr.Scheme == "http" {
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
		if cfg.Addr.Port == "" && ((!cfg.TLS.Manual && !cfg.TLS.SelfSigned) || cfg.TLS.Manager.OnDemand != nil) {
			// this is vital, otherwise the function call below that
			// sets the listener address will use the default port
			// instead of 443 because it doesn't know about TLS.
			cfg.Addr.Port = httpsPort
		}
		if cfg.TLS.ClientAuth != tls.NoClientCert {
			if QUIC {
				return nil, fmt.Errorf("cannot enable TLS client authentication with QUIC, because QUIC does not yet support it")
			}
			// this must be enabled so that a client cannot connect
			// using SNI for another site on this listener that
			// does NOT require ClientAuth, and then send HTTP
			// requests with the Host header of this site which DOES
			// require client auth, thus bypassing it...
			cfg.StrictHostMatching = true
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

	// NOTE: This value is only a "good guess". Quite often, development
	// environments will use internal DNS or a local hosts file to serve
	// real-looking domains in local development. We can't easily tell
	// which without doing a DNS lookup, so this guess is definitely naive,
	// and if we ever want a better guess, we will have to do DNS lookups.
	deploymentGuess := "dev"
	if looksLikeProductionCA && atLeastOneSiteLooksLikeProduction {
		deploymentGuess = "prod"
	}
	telemetry.Set("http_deployment_guess", deploymentGuess)
	telemetry.Set("http_num_sites", len(h.siteConfigs))

	return servers, nil
}

// normalizedKey returns "normalized" key representation:
//  scheme and host names are lowered, everything else stays the same
func normalizedKey(key string) string {
	addr, err := standardizeAddress(key)
	if err != nil {
		return key
	}
	return addr.Normalize().Key()
}

// GetConfig gets the SiteConfig that corresponds to c.
// If none exist (should only happen in tests), then a
// new, empty one will be created.
func GetConfig(c *caddy.Controller) *SiteConfig {
	ctx := c.Context().(*httpContext)
	key := normalizedKey(c.Key)
	if cfg, ok := ctx.keysToSiteConfigs[key]; ok {
		return cfg
	}
	// we should only get here during tests because directive
	// actions typically skip the server blocks where we make
	// the configs
	cfg := &SiteConfig{
		Root:       Root,
		TLS:        &caddytls.Config{Manager: certmagic.NewDefault()},
		IndexPages: staticfiles.DefaultIndexPages,
	}
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
//
// The Host field must be in a normalized form.
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
		if a.Port == strconv.Itoa(certmagic.HTTPSPort) {
			scheme = "https"
		} else {
			scheme = "http"
		}
	}
	s := scheme
	if s != "" {
		s += "://"
	}
	if a.Port != "" &&
		((scheme == "https" && a.Port != DefaultHTTPSPort) ||
			(scheme == "http" && a.Port != DefaultHTTPPort)) {
		s += net.JoinHostPort(a.Host, a.Port)
	} else {
		s += a.Host
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

// Normalize normalizes URL: turn scheme and host names into lower case
func (a Address) Normalize() Address {
	path := a.Path
	if !CaseSensitivePath {
		path = strings.ToLower(path)
	}

	// ensure host is normalized if it's an IP address
	host := a.Host
	if ip := net.ParseIP(host); ip != nil {
		host = ip.String()
	}

	return Address{
		Original: a.Original,
		Scheme:   strings.ToLower(a.Scheme),
		Host:     strings.ToLower(host),
		Port:     a.Port,
		Path:     path,
	}
}

// Key is similar to String, just replaces scheme and host values with modified values.
// Unlike String it doesn't add anything default (scheme, port, etc)
func (a Address) Key() string {
	res := ""
	if a.Scheme != "" {
		res += a.Scheme + "://"
	}
	if a.Host != "" {
		res += a.Host
	}
	// insert port only if the original has its own explicit port
	if a.Port != "" && len(a.Original) >= len(res) &&
		strings.HasPrefix(a.Original[len(res):], ":"+a.Port) {
		res += ":" + a.Port
	}
	if a.Path != "" {
		res += a.Path
	}
	return res
}

// standardizeAddress parses an address string into a structured format with separate
// scheme, host, port, and path portions, as well as the original input string.
func standardizeAddress(str string) (Address, error) {
	input := str

	httpPort := strconv.Itoa(certmagic.HTTPPort)
	httpsPort := strconv.Itoa(certmagic.HTTPSPort)

	// As of Go 1.12.8 (Aug 2019), ports that are service names such
	// as ":http" and ":https" are no longer parsed as they were
	// before, which is a breaking change for us. Attempt to smooth
	// this over for now by replacing those strings with their port
	// equivalents. See
	// https://github.com/golang/go/commit/3226f2d492963d361af9dfc6714ef141ba606713
	str = strings.Replace(str, ":https", ":"+httpsPort, 1)
	str = strings.Replace(str, ":http", ":"+httpPort, 1)

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
			port = httpPort
		} else if u.Scheme == "https" {
			port = httpsPort
		}
	}

	// error if scheme and port combination violate convention
	if (u.Scheme == "http" && port == httpsPort) || (u.Scheme == "https" && port == httpPort) {
		return Address{}, fmt.Errorf("[%s] scheme and port violate convention", input)
	}

	// standardize http and https ports to their respective port numbers
	// (this behavior changed in Go 1.12.8)
	if u.Scheme == "" {
		if port == httpPort {
			u.Scheme = "http"
		} else if port == httpsPort {
			u.Scheme = "https"
		}
	}

	return Address{Original: input, Scheme: u.Scheme, Host: host, Port: port, Path: u.Path}, nil
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
	"supervisor", // github.com/lucaslorentz/caddy-supervisor
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
	"minify", // github.com/hacdias/caddy-minify
	"gzip",
	"header",
	"geoip", // github.com/kodnaplakal/caddy-geoip
	"errors",
	"authz",        // github.com/casbin/caddy-authz
	"filter",       // github.com/echocat/caddy-filter
	"ipfilter",     // github.com/pyed/ipfilter
	"ratelimit",    // github.com/xuqingfeng/caddy-rate-limit
	"recaptcha",    // github.com/defund/caddy-recaptcha
	"expires",      // github.com/epicagency/caddy-expires
	"forwardproxy", // github.com/caddyserver/forwardproxy
	"basicauth",
	"redir",
	"status",
	"cors",      // github.com/captncraig/cors/caddy
	"s3browser", // github.com/techknowlogick/caddy-s3browser
	"nobots",    // github.com/Xumeiquer/nobots
	"mime",
	"login",      // github.com/tarent/loginsrv/caddy
	"reauth",     // github.com/freman/caddy-reauth
	"extauth",    // github.com/BTBurke/caddy-extauth
	"jwt",        // github.com/BTBurke/caddy-jwt
	"permission", // github.com/dhaavi/caddy-permission
	"jsonp",      // github.com/pschlump/caddy-jsonp
	"upload",     // blitznote.com/src/caddy.upload
	"multipass",  // github.com/namsral/multipass/caddy
	"internal",
	"pprof",
	"expvar",
	"push",
	"datadog",    // github.com/payintech/caddy-datadog
	"prometheus", // github.com/miekg/caddy-prometheus
	"templates",
	"proxy",
	"pubsub", // github.com/jung-kurt/caddy-pubsub
	"fastcgi",
	"cgi", // github.com/jung-kurt/caddy-cgi
	"websocket",
	"filebrowser", // github.com/filebrowser/caddy
	"webdav",      // github.com/hacdias/caddy-webdav
	"markdown",
	"browse",
	"mailout",   // github.com/SchumacherFM/mailout
	"awses",     // github.com/miquella/caddy-awses
	"awslambda", // github.com/coopernurse/caddy-awslambda
	"grpc",      // github.com/pieterlouw/caddy-grpc
	"gopkg",     // github.com/zikes/gopkg
	"restic",    // github.com/restic/caddy
	"wkd",       // github.com/emersion/caddy-wkd
	"dyndns",    // github.com/linkonoid/caddy-dyndns
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
)
