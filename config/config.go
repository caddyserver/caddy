package config

import (
	"io"
	"log"

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

// The application should set these so that various middlewares
// can access the proper information for their own needs.
var AppName, AppVersion string
