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

	// The protocol (http/https) to serve with this config; only set if user explicitly specifies it
	Scheme string

	// The directory from which to serve files
	Root string

	// HTTPS configuration
	TLS TLSConfig

	// Middleware stack
	Middleware []middleware.Middleware

	// Startup is a list of functions (or methods) to execute at
	// server startup and restart; these are executed before any
	// parts of the server are configured, and the functions are
	// blocking. These are good for setting up middlewares and
	// starting goroutines.
	Startup []func() error

	// FirstStartup is like Startup but these functions only execute
	// during the initial startup, not on subsequent restarts.
	//
	// (Note: The server does not ever run these on its own; it is up
	// to the calling application to do so, and do so only once, as the
	// server itself has no notion whether it's a restart or not.)
	FirstStartup []func() error

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

// TLSConfig describes how TLS should be configured and used.
type TLSConfig struct {
	Enabled                  bool // will be set to true if TLS is enabled
	LetsEncryptEmail         string
	Manual                   bool // will be set to true if user provides own certs and keys
	Managed                  bool // will be set to true if config qualifies for implicit automatic/managed HTTPS
	OnDemand                 bool // will be set to true if user enables on-demand TLS (obtain certs during handshakes)
	Ciphers                  []uint16
	ProtocolMinVersion       uint16
	ProtocolMaxVersion       uint16
	PreferServerCipherSuites bool
	ClientCerts              []string
}
