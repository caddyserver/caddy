package httpserver

import (
	"flag"
	"fmt"
	"log"
	"net"
	"net/url"
	"strings"
	"time"

	"github.com/mholt/caddy"
	"github.com/mholt/caddy/caddyfile"
	"github.com/mholt/caddy/caddytls"
)

const serverType = "http"

func init() {
	flag.StringVar(&Host, "host", DefaultHost, "Default host")
	flag.StringVar(&Port, "port", DefaultPort, "Default port")
	flag.StringVar(&Root, "root", DefaultRoot, "Root path of default site")
	flag.DurationVar(&GracefulTimeout, "grace", 5*time.Second, "Maximum duration of graceful shutdown") // TODO
	flag.BoolVar(&HTTP2, "http2", true, "Use HTTP/2")
	flag.BoolVar(&QUIC, "quic", false, "Use experimental QUIC")

	caddy.RegisterServerType(serverType, caddy.ServerType{
		Directives: directives,
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
	caddy.RegisterParsingCallback(serverType, "tls", activateHTTPS)
	caddytls.RegisterConfigGetter(serverType, func(key string) *caddytls.Config { return GetConfig(key).TLS })
}

var contexts []*httpContext

func newContext() caddy.Context {
	context := &httpContext{keysToSiteConfigs: make(map[string]*SiteConfig)}
	contexts = append(contexts, context)
	return context
}

type httpContext struct {
	// keysToSiteConfigs maps an address at the top of a
	// server block (a "key") to its SiteConfig. Not all
	// SiteConfigs will be represented here, only ones
	// that appeared in the Caddyfile.
	keysToSiteConfigs map[string]*SiteConfig

	// siteConfigs is the master list of all site configs.
	siteConfigs []*SiteConfig
}

// InspectServerBlocks make sure that everything checks out before
// executing directives and otherwise prepares the directives to
// be parsed and executed.
func (h *httpContext) InspectServerBlocks(sourceFile string, serverBlocks []caddyfile.ServerBlock) ([]caddyfile.ServerBlock, error) {
	// TODO: Here we can inspect the server blocks
	// and make changes to them, like adding a directive
	// that must always be present (e.g. 'errors discard`?) -
	// totally optional; server types need not register this
	// function.

	// For each address in each server block, make a new config
	for _, sb := range serverBlocks {
		for _, key := range sb.Keys {
			key = strings.ToLower(key)
			if _, dup := h.keysToSiteConfigs[key]; dup {
				return serverBlocks, fmt.Errorf("duplicate site address: %s", key)
			}
			addr, err := standardizeAddress(key)
			if err != nil {
				return serverBlocks, err
			}
			// Save the config to our master list, and key it for lookups
			cfg := &SiteConfig{
				Addr:        addr,
				TLS:         &caddytls.Config{Hostname: addr.Host},
				HiddenFiles: []string{sourceFile},
			}
			h.siteConfigs = append(h.siteConfigs, cfg)
			h.keysToSiteConfigs[key] = cfg
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
		if cfg.TLS.Enabled && (cfg.Addr.Port == "80" || cfg.Addr.Scheme == "http") {
			cfg.TLS.Enabled = false
			log.Printf("[WARNING] TLS disabled for %s", cfg.Addr)
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

// GetConfig gets a SiteConfig that is keyed by addrKey.
// It creates an empty one in the latest context if
// the key does not exist in any context, so it
// will never return nil. If no contexts exist (which
// should never happen except in tests), it creates a
// new context in which to put it.
func GetConfig(addrKey string) *SiteConfig {
	for _, context := range contexts {
		if cfg, ok := context.keysToSiteConfigs[addrKey]; ok {
			return cfg
		}
	}
	if len(contexts) == 0 {
		// this shouldn't happen except in tests
		newContext()
	}
	cfg := new(SiteConfig)
	cfg.TLS = new(caddytls.Config)
	defaultCtx := contexts[len(contexts)-1]
	defaultCtx.siteConfigs = append(defaultCtx.siteConfigs, cfg)
	defaultCtx.keysToSiteConfigs[addrKey] = cfg
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
		if caddy.IsLoopback(conf.Addr.Host) && conf.ListenHost == "" {
			// special case: one would not expect a site served
			// at loopback to be connected to from the outside.
			conf.ListenHost = conf.Addr.Host
		}
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

// AddMiddleware adds a middleware to a site's middleware stack.
func (sc *SiteConfig) AddMiddleware(m Middleware) {
	sc.middleware = append(sc.middleware, m)
}

// Address represents a site address. It contains
// the original input value, and the component
// parts of an address.
type Address struct {
	Original, Scheme, Host, Port, Path string
}

// String returns a human-friendly print of the address.
func (a Address) String() string {
	scheme := a.Scheme
	if scheme == "" {
		if a.Port == "80" {
			scheme = "http"
		} else if a.Port == "443" {
			scheme = "https"
		}
	}
	s := scheme
	if s != "" {
		s += "://"
	}
	s += a.Host
	if (scheme == "https" && a.Port != "443") ||
		(scheme == "http" && a.Port != "80") {
		s += ":" + a.Port
	}
	if a.Path != "" {
		s += "/" + a.Path
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
// scheme, host, and port portions, as well as the original input string.
func standardizeAddress(str string) (Address, error) {
	input := str

	// Split input into components (prepend with // to assert host by default)
	if !strings.Contains(str, "//") {
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
			port = "80"
		} else if u.Scheme == "https" {
			port = "443"
		}
	}

	// repeated or conflicting scheme is confusing, so error
	if u.Scheme != "" && (port == "http" || port == "https") {
		return Address{}, fmt.Errorf("[%s] scheme specified twice in address", input)
	}

	// error if scheme and port combination violate convention
	if (u.Scheme == "http" && port == "443") || (u.Scheme == "https" && port == "80") {
		return Address{}, fmt.Errorf("[%s] scheme and port violate convention", input)
	}

	// standardize http and https ports to their respective port numbers
	if port == "http" {
		u.Scheme = "http"
		port = "80"
	} else if port == "https" {
		u.Scheme = "https"
		port = "443"
	}

	return Address{Original: input, Scheme: u.Scheme, Host: host, Port: port, Path: u.Path}, err
}

// directives is the list of all directives known to exist for the
// http server type, including non-standard (3rd-party) directives.
// The ordering of this list is important.
var directives = []string{
	// primitive actions that set up the basics of each config
	"root",
	"bind",
	"tls",

	// these don't inject middleware handlers
	"startup",
	"shutdown",

	// these add middleware to the stack
	"log",
	"gzip",
	"errors",
	"header",
	"rewrite",
	"redir",
	"ext",
	"mime",
	"basicauth",
	"internal",
	"pprof",
	"expvar",
	"proxy",
	"fastcgi",
	"websocket",
	"markdown",
	"templates",
	"browse",
}

const (
	// DefaultHost is the default host.
	DefaultHost = ""
	// DefaultPort is the default port.
	DefaultPort = "2015"
	// DefaultRoot is the default root folder.
	DefaultRoot = "."
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
