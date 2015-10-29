package caddy

import (
	"fmt"
	"io"
	"log"
	"net"
	"sync"

	"github.com/mholt/caddy/caddy/parse"
	"github.com/mholt/caddy/caddy/setup"
	"github.com/mholt/caddy/middleware"
	"github.com/mholt/caddy/server"
)

const (
	// DefaultConfigFile is the name of the configuration file that is loaded
	// by default if no other file is specified.
	DefaultConfigFile = "Caddyfile"
)

// load reads input (named filename) and parses it, returning the
// server configurations in the order they appeared in the input.
func load(filename string, input io.Reader) ([]server.Config, error) {
	var configs []server.Config

	// turn off timestamp for parsing
	flags := log.Flags()
	log.SetFlags(0)

	serverBlocks, err := parse.ServerBlocks(filename, input, true)
	if err != nil {
		return nil, err
	}
	if len(serverBlocks) == 0 {
		return []server.Config{NewDefault()}, nil
	}

	// Each server block represents similar hosts/addresses.
	// Iterate each server block and make a config for each one,
	// executing the directives that were parsed.
	for i, sb := range serverBlocks {
		onces := makeOnces()
		storages := makeStorages()

		for j, addr := range sb.Addresses {
			config := server.Config{
				Host:       addr.Host,
				Port:       addr.Port,
				Root:       Root,
				Middleware: make(map[string][]middleware.Middleware),
				ConfigFile: filename,
				AppName:    AppName,
				AppVersion: AppVersion,
			}

			// It is crucial that directives are executed in the proper order.
			for _, dir := range directiveOrder {
				// Execute directive if it is in the server block
				if tokens, ok := sb.Tokens[dir.name]; ok {
					// Each setup function gets a controller, which is the
					// server config and the dispenser containing only
					// this directive's tokens.
					controller := &setup.Controller{
						Config:    &config,
						Dispenser: parse.NewDispenserTokens(filename, tokens),
						OncePerServerBlock: func(f func() error) error {
							var err error
							onces[dir.name].Do(func() {
								err = f()
							})
							return err
						},
						ServerBlockIndex:     i,
						ServerBlockHostIndex: j,
						ServerBlockHosts:     sb.HostList(),
						ServerBlockStorage:   storages[dir.name],
					}

					midware, err := dir.setup(controller)
					if err != nil {
						return nil, err
					}
					if midware != nil {
						// TODO: For now, we only support the default path scope /
						config.Middleware["/"] = append(config.Middleware["/"], midware)
					}
					storages[dir.name] = controller.ServerBlockStorage // persist for this server block
				}
			}

			if config.Port == "" {
				config.Port = Port
			}

			configs = append(configs, config)
		}
	}

	// restore logging settings
	log.SetFlags(flags)

	return configs, nil
}

// makeOnces makes a map of directive name to sync.Once
// instance. This is intended to be called once per server
// block when setting up configs so that Setup functions
// for each directive can perform a task just once per
// server block, even if there are multiple hosts on the block.
//
// We need one Once per directive, otherwise the first
// directive to use it would exclude other directives from
// using it at all, which would be a bug.
func makeOnces() map[string]*sync.Once {
	onces := make(map[string]*sync.Once)
	for _, dir := range directiveOrder {
		onces[dir.name] = new(sync.Once)
	}
	return onces
}

// makeStorages makes a map of directive name to interface{}
// so that directives' setup functions can persist state
// between different hosts on the same server block during the
// setup phase.
func makeStorages() map[string]interface{} {
	storages := make(map[string]interface{})
	for _, dir := range directiveOrder {
		storages[dir.name] = nil
	}
	return storages
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
	var groupings Group

	// Group configs by bind address
	for _, conf := range allConfigs {
		bindAddr, warnErr, fatalErr := resolveAddr(conf)
		if fatalErr != nil {
			return groupings, fatalErr
		}
		if warnErr != nil {
			log.Println("[Warning]", warnErr)
		}

		// Make sure to compare the string representation of the address,
		// not the pointer, since a new *TCPAddr is created each time.
		var existing bool
		for i := 0; i < len(groupings); i++ {
			if groupings[i].BindAddr.String() == bindAddr.String() {
				groupings[i].Configs = append(groupings[i].Configs, conf)
				existing = true
				break
			}
		}
		if !existing {
			groupings = append(groupings, BindingMapping{
				BindAddr: bindAddr,
				Configs:  []server.Config{conf},
			})
		}
	}

	// Don't allow HTTP and HTTPS to be served on the same address
	for _, group := range groupings {
		isTLS := group.Configs[0].TLS.Enabled
		for _, config := range group.Configs {
			if config.TLS.Enabled != isTLS {
				thisConfigProto, otherConfigProto := "HTTP", "HTTP"
				if config.TLS.Enabled {
					thisConfigProto = "HTTPS"
				}
				if group.Configs[0].TLS.Enabled {
					otherConfigProto = "HTTPS"
				}
				return groupings, fmt.Errorf("configuration error: Cannot multiplex %s (%s) and %s (%s) on same address",
					group.Configs[0].Address(), otherConfigProto, config.Address(), thisConfigProto)
			}
		}
	}

	return groupings, nil
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

// NewDefault makes a default configuration, which
// is empty except for root, host, and port,
// which are essentials for serving the cwd.
func NewDefault() server.Config {
	return server.Config{
		Root: Root,
		Host: Host,
		Port: Port,
	}
}

// These defaults are configurable through the command line
var (
	// Site root
	Root = DefaultRoot

	// Site host
	Host = DefaultHost

	// Site port
	Port = DefaultPort
)

// BindingMapping maps a network address to configurations
// that will bind to it. The order of the configs is important.
type BindingMapping struct {
	BindAddr *net.TCPAddr
	Configs  []server.Config
}

// Group maps network addresses to their configurations.
// Preserving the order of the groupings is important
// (related to graceful shutdown and restart)
// so this is a slice, not a literal map.
type Group []BindingMapping
