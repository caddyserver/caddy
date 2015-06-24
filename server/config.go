package server

import (
	"net"

	"github.com/mholt/caddy/middleware"
)

// Config configuration for a single server.
type Config struct {
	// The hostname or IP on which to serve
	Host string

	// The host address to bind on - defaults to (virtual) Host if empty
	BindHost string

	// The port to listen on
	Port string

	// The directory from which to serve files
	Root string

	// HTTPS configuration
	TLS TLSConfig

	// Middleware stack; map of path scope to middleware -- TODO: Support path scope?
	Middleware map[string][]middleware.Middleware

	// Functions (or methods) to execute at server start; these
	// are executed before any parts of the server are configured,
	// and the functions are blocking
	Startup []func() error

	// Functions (or methods) to execute when the server quits;
	// these are executed in response to SIGINT and are blocking
	Shutdown []func() error

	// The path to the configuration file from which this was loaded
	ConfigFile string

	// The name of the application
	AppName string

	// The application's version
	AppVersion string
}

// Address returns the host:port of c as a string.
func (c Config) Address() string {
	return net.JoinHostPort(c.Host, c.Port)
}

// TLSConfig describes how TLS should be configured and used,
// if at all. A certificate and key are both required.
// The rest is optional.
type TLSConfig struct {
	Enabled                  bool
	Certificate              string
	Key                      string
	Ciphers                  []uint16
	ProtocolMinVersion       uint16
	ProtocolMaxVersion       uint16
	PreferServerCipherSuites bool
	ClientCerts              []string
}
