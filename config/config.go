package config

import (
	"fmt"
	"io"
	"log"
	"net"

	"github.com/mholt/caddy/app"
	"github.com/mholt/caddy/config/parse"
	"github.com/mholt/caddy/config/setup"
	"github.com/mholt/caddy/middleware"
	"github.com/mholt/caddy/server"
)

const (
	DefaultHost = "0.0.0.0"
	DefaultPort = "2015"
	DefaultRoot = "."

	// DefaultConfigFile is the name of the configuration file that is loaded
	// by default if no other file is specified.
	DefaultConfigFile = "Caddyfile"
)

// Load reads input (named filename) and parses it, returning server
// configurations grouped by listening address.
func Load(filename string, input io.Reader) (Group, error) {
	var configs []server.Config

	// turn off timestamp for parsing
	flags := log.Flags()
	log.SetFlags(0)

	serverBlocks, err := parse.ServerBlocks(filename, input)
	if err != nil {
		return nil, err
	}
	if len(serverBlocks) == 0 {
		return Default()
	}

	// Each server block represents one or more servers/addresses.
	// Iterate each server block and make a config for each one,
	// executing the directives that were parsed.
	for _, sb := range serverBlocks {
		sharedConfig, err := serverBlockToConfig(filename, sb)
		if err != nil {
			return nil, err
		}

		// Now share the config with as many hosts as share the server block
		for i, addr := range sb.Addresses {
			config := sharedConfig
			config.Host = addr.Host
			config.Port = addr.Port
			if config.Port == "" {
				config.Port = Port
			}
			if config.Port == "http" {
				config.TLS.Enabled = false
				log.Printf("Warning: TLS disabled for %s://%s. To force TLS over the plaintext HTTP port, "+
					"specify port 80 explicitly (https://%s:80).", config.Port, config.Host, config.Host)
			}
			if i == 0 {
				sharedConfig.Startup = []func() error{}
				sharedConfig.Shutdown = []func() error{}
			}
			configs = append(configs, config)
		}
	}

	// restore logging settings
	log.SetFlags(flags)

	// Group by address/virtualhosts
	return arrangeBindings(configs)
}

// serverBlockToConfig makes a config for the server block
// by executing the tokens that were parsed. The returned
// config is shared among all hosts/addresses for the server
// block, so Host and Port information is not filled out
// here.
func serverBlockToConfig(filename string, sb parse.ServerBlock) (server.Config, error) {
	sharedConfig := server.Config{
		Root:       Root,
		Middleware: make(map[string][]middleware.Middleware),
		ConfigFile: filename,
		AppName:    app.Name,
		AppVersion: app.Version,
	}

	// It is crucial that directives are executed in the proper order.
	for _, dir := range directiveOrder {
		// Execute directive if it is in the server block
		if tokens, ok := sb.Tokens[dir.name]; ok {
			// Each setup function gets a controller, which is the
			// server config and the dispenser containing only
			// this directive's tokens.
			controller := &setup.Controller{
				Config:    &sharedConfig,
				Dispenser: parse.NewDispenserTokens(filename, tokens),
			}

			midware, err := dir.setup(controller)
			if err != nil {
				return sharedConfig, err
			}
			if midware != nil {
				// TODO: For now, we only support the default path scope /
				sharedConfig.Middleware["/"] = append(sharedConfig.Middleware["/"], midware)
			}
		}
	}

	return sharedConfig, nil
}

// arrangeBindings groups configurations by their bind address. For example,
// a server that should listen on localhost and another on 127.0.0.1 will
// be grouped into the same address: 127.0.0.1. It will return an error
// if an address is malformed or a TLS listener is configured on the
// same address as a plaintext HTTP listener. The return value is a map of
// bind address to list of configs that would become VirtualHosts on that
// server. Use the keys of the returned map to create listeners, and use
// the associated values to set up the virtualhosts.
func arrangeBindings(allConfigs []server.Config) (Group, error) {
	addresses := make(Group)

	// Group configs by bind address
	for _, conf := range allConfigs {
		newAddr, warnErr, fatalErr := resolveAddr(conf)
		if fatalErr != nil {
			return addresses, fatalErr
		}
		if warnErr != nil {
			log.Println("[Warning]", warnErr)
		}

		// Make sure to compare the string representation of the address,
		// not the pointer, since a new *TCPAddr is created each time.
		var existing bool
		for addr := range addresses {
			if addr.String() == newAddr.String() {
				addresses[addr] = append(addresses[addr], conf)
				existing = true
				break
			}
		}
		if !existing {
			addresses[newAddr] = append(addresses[newAddr], conf)
		}
	}

	// Don't allow HTTP and HTTPS to be served on the same address
	for _, configs := range addresses {
		isTLS := configs[0].TLS.Enabled
		for _, config := range configs {
			if config.TLS.Enabled != isTLS {
				thisConfigProto, otherConfigProto := "HTTP", "HTTP"
				if config.TLS.Enabled {
					thisConfigProto = "HTTPS"
				}
				if configs[0].TLS.Enabled {
					otherConfigProto = "HTTPS"
				}
				return addresses, fmt.Errorf("configuration error: Cannot multiplex %s (%s) and %s (%s) on same address",
					configs[0].Address(), otherConfigProto, config.Address(), thisConfigProto)
			}
		}
	}

	return addresses, nil
}

// resolveAddr determines the address (host and port) that a config will
// bind to. The returned address, resolvAddr, should be used to bind the
// listener or group the config with other configs using the same address.
// The first error, if not nil, is just a warning and should be reported
// but execution may continue. The second error, if not nil, is a real
// problem and the server should not be started.
//
// This function handles edge cases gracefully. If a port name like
// "http" or "https" is unknown to the system, this function will
// change them to 80 or 443 respectively. If a hostname fails to
// resolve, that host can still be served but will be listening on
// the wildcard host instead. This function takes care of this for you.
func resolveAddr(conf server.Config) (resolvAddr *net.TCPAddr, warnErr error, fatalErr error) {
	bindHost := conf.BindHost

	resolvAddr, warnErr = net.ResolveTCPAddr("tcp", net.JoinHostPort(bindHost, conf.Port))
	if warnErr != nil {
		// Most likely the host lookup failed or the port is unknown
		tryPort := conf.Port

		switch errVal := warnErr.(type) {
		case *net.AddrError:
			if errVal.Err == "unknown port" {
				// some odd Linux machines don't support these port names; see issue #136
				switch conf.Port {
				case "http":
					tryPort = "80"
				case "https":
					tryPort = "443"
				}
			}
			resolvAddr, fatalErr = net.ResolveTCPAddr("tcp", net.JoinHostPort(bindHost, tryPort))
			if fatalErr != nil {
				return
			}
		default:
			// the hostname probably couldn't be resolved, just bind to wildcard then
			resolvAddr, fatalErr = net.ResolveTCPAddr("tcp", net.JoinHostPort("0.0.0.0", tryPort))
			if fatalErr != nil {
				return
			}
		}

		return
	}

	return
}

// validDirective returns true if d is a valid
// directive; false otherwise.
func validDirective(d string) bool {
	for _, dir := range directiveOrder {
		if dir.name == d {
			return true
		}
	}
	return false
}

func NewDefault() server.Config {
	return server.Config{
		Root: Root,
		Host: Host,
		Port: Port,
	}
}

// Default makes a default configuration which
// is empty except for root, host, and port,
// which are essentials for serving the cwd.
func Default() (Group, error) {
	return arrangeBindings([]server.Config{NewDefault()})
}

// These three defaults are configurable through the command line
var (
	Root = DefaultRoot
	Host = DefaultHost
	Port = DefaultPort
)

type Group map[*net.TCPAddr][]server.Config
