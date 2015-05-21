package config

import (
	"errors"
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

	// The default configuration file to load if none is specified
	DefaultConfigFile = "Caddyfile"
)

func Load(filename string, input io.Reader) ([]server.Config, error) {
	var configs []server.Config

	// turn off timestamp for parsing
	flags := log.Flags()
	log.SetFlags(0)

	serverBlocks, err := parse.ServerBlocks(filename, input)
	if err != nil {
		return configs, err
	}

	// Each server block represents a single server/address.
	// Iterate each server block and make a config for each one,
	// executing the directives that were parsed.
	for _, sb := range serverBlocks {
		config := server.Config{
			Host:       sb.Host,
			Port:       sb.Port,
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
					Config:    &config,
					Dispenser: parse.NewDispenserTokens(filename, tokens),
				}

				midware, err := dir.setup(controller)
				if err != nil {
					return configs, err
				}
				if midware != nil {
					// TODO: For now, we only support the default path scope /
					config.Middleware["/"] = append(config.Middleware["/"], midware)
				}
			}
		}

		if config.Port == "" {
			config.Port = Port
		}

		configs = append(configs, config)
	}

	// restore logging settings
	log.SetFlags(flags)

	return configs, nil
}

// ArrangeBindings groups configurations by their bind address. For example,
// a server that should listen on localhost and another on 127.0.0.1 will
// be grouped into the same address: 127.0.0.1. It will return an error
// if the address lookup fails or if a TLS listener is configured on the
// same address as a plaintext HTTP listener. The return value is a map of
// bind address to list of configs that would become VirtualHosts on that
// server.
func ArrangeBindings(allConfigs []server.Config) (map[*net.TCPAddr][]server.Config, error) {
	addresses := make(map[*net.TCPAddr][]server.Config)

	// Group configs by bind address
	for _, conf := range allConfigs {
		newAddr, err := net.ResolveTCPAddr("tcp", conf.Address())
		if err != nil {
			return addresses, errors.New("Could not serve " + conf.Address() + " - " + err.Error())
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
				return addresses, fmt.Errorf("Configuration error: Cannot multiplex %s (%s) and %s (%s) on same address",
					configs[0].Address(), otherConfigProto, config.Address(), thisConfigProto)
			}
		}
	}

	return addresses, nil
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

// Default makes a default configuration which
// is empty except for root, host, and port,
// which are essentials for serving the cwd.
func Default() server.Config {
	return server.Config{
		Root: Root,
		Host: Host,
		Port: Port,
	}
}

// These three defaults are configurable through the command line
var (
	Root = DefaultRoot
	Host = DefaultHost
	Port = DefaultPort
)
