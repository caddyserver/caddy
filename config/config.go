// Package config contains utilities and types necessary for
// launching specially-configured server instances.
package config

import (
	"os"

	"github.com/mholt/caddy/middleware"
)

const (
	defaultHost = "localhost"
	defaultPort = "8080"
	defaultRoot = "."
)

// Load loads a configuration file, parses it,
// and returns a slice of Config structs which
// can be used to create and configure server
// instances.
func Load(filename string) ([]Config, error) {
	file, err := os.Open(filename)
	if err != nil {
		return nil, err
	}
	defer file.Close()
	p := newParser(file)
	return p.parse()
}

// IsNotFound returns whether or not the error is
// one which indicates that the configuration file
// was not found. (Useful for checking the error
// returned from Load).
func IsNotFound(err error) bool {
	return os.IsNotExist(err)
}

// Default makes a default configuration
// that's empty except for root, host, and port,
// which are essential for serving the cwd.
func Default() []Config {
	cfg := []Config{
		Config{
			Root: defaultRoot,
			Host: defaultHost,
			Port: defaultPort,
		},
	}
	return cfg
}

// config represents a server configuration. It
// is populated by parsing a config file (via the
// Load function).
type Config struct {
	Host       string
	Port       string
	Root       string
	TLS        TLSConfig
	Middleware []middleware.Middleware
	Startup    []func() error
}

// Address returns the host:port of c as a string.
func (c Config) Address() string {
	return c.Host + ":" + c.Port
}

// TLSConfig describes how TLS should be configured and used,
// if at all. At least a certificate and key are required.
type TLSConfig struct {
	Enabled     bool
	Certificate string
	Key         string
}
