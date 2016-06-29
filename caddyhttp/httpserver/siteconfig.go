package httpserver

import "github.com/mholt/caddy/caddytls"

// SiteConfig contains information about a site
// (also known as a virtual host).
type SiteConfig struct {
	// The address of the site
	Addr Address

	// The hostname to bind listener to;
	// defaults to Addr.Host
	ListenHost string

	// TLS configuration
	TLS *caddytls.Config

	// Uncompiled middleware stack
	middleware []Middleware

	// Compiled middleware stack
	middlewareChain Handler

	// Directory from which to serve files
	Root string

	// A list of files to hide (for example, the
	// source Caddyfile). TODO: Enforcing this
	// should be centralized, for example, a
	// standardized way of loading files from disk
	// for a request.
	HiddenFiles []string
}

// AddMiddleware adds a middleware to a site's middleware stack.
func (s *SiteConfig) AddMiddleware(m Middleware) {
	s.middleware = append(s.middleware, m)
}

// TLSConfig returns s.TLS.
func (s SiteConfig) TLSConfig() *caddytls.Config {
	return s.TLS
}

// Host returns s.Addr.Host.
func (s SiteConfig) Host() string {
	return s.Addr.Host
}

// Port returns s.Addr.Port.
func (s SiteConfig) Port() string {
	return s.Addr.Port
}

// Middleware returns s.middleware (useful for tests).
func (s SiteConfig) Middleware() []Middleware {
	return s.middleware
}
