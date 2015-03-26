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

// config represents a server configuration. It
// is populated by parsing a config file (via the
// Load function).
type Config struct {
	// The hostname or IP to which to bind the server
	Host string

	// The port to listen on
	Port string

	// The directory from which to serve files
	Root string

	// HTTPS configuration
	TLS TLSConfig

	// Middleware stack
	Middleware map[string][]middleware.Middleware

	// Functions (or methods) to execute at server start; these
	// are executed before any parts of the server are configured,
	// and the functions are blocking
	Startup []func() error

	// Functions (or methods) to execute when the server quits;
	// these are executed in response to SIGINT and are blocking
	Shutdown []func() error

	// MaxCPU is the maximum number of cores for the whole process to use
	MaxCPU int
}

// Address returns the host:port of c as a string.
func (c Config) Address() string {
	return c.Host + ":" + c.Port
}

// TLSConfig describes how TLS should be configured and used,
// if at all. A certificate and key are both required.
type TLSConfig struct {
	Enabled     bool
	Certificate string
	Key         string
}

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

	p, err := newParser(file)
	if err != nil {
		return nil, err
	}

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
