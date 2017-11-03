// Copyright 2015 Light Code Labs, LLC
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package httpserver

import (
	"time"

	"github.com/mholt/caddy/caddytls"
)

// SiteConfig contains information about a site
// (also known as a virtual host).
type SiteConfig struct {
	// The address of the site
	Addr Address

	// The list of viable index page names of the site
	IndexPages []string

	// The hostname to bind listener to;
	// defaults to Addr.Host
	ListenHost string

	// TLS configuration
	TLS *caddytls.Config

	// Uncompiled middleware stack
	middleware []Middleware

	// Compiled middleware stack
	middlewareChain Handler

	// listener middleware stack
	listenerMiddleware []ListenerMiddleware

	// Directory from which to serve files
	Root string

	// A list of files to hide (for example, the
	// source Caddyfile). TODO: Enforcing this
	// should be centralized, for example, a
	// standardized way of loading files from disk
	// for a request.
	HiddenFiles []string

	// Max request's header/body size
	Limits Limits

	// The path to the Caddyfile used to generate this site config
	originCaddyfile string

	// These timeout values are used, in conjunction with other
	// site configs on the same server instance, to set the
	// respective timeout values on the http.Server that
	// is created. Sensible values will mitigate slowloris
	// attacks and overcome faulty networks, while still
	// preserving functionality needed for proxying,
	// websockets, etc.
	Timeouts Timeouts

	// If true, any requests not matching other site definitions
	// may be served by this site.
	FallbackSite bool
}

// Timeouts specify various timeouts for a server to use.
// If the assocated bool field is true, then the duration
// value should be treated literally (i.e. a zero-value
// duration would mean "no timeout"). If false, the duration
// was left unset, so a zero-value duration would mean to
// use a default value (even if default is non-zero).
type Timeouts struct {
	ReadTimeout          time.Duration
	ReadTimeoutSet       bool
	ReadHeaderTimeout    time.Duration
	ReadHeaderTimeoutSet bool
	WriteTimeout         time.Duration
	WriteTimeoutSet      bool
	IdleTimeout          time.Duration
	IdleTimeoutSet       bool
}

// Limits specify size limit of request's header and body.
type Limits struct {
	MaxRequestHeaderSize int64
	MaxRequestBodySizes  []PathLimit
}

// PathLimit is a mapping from a site's path to its corresponding
// maximum request body size (in bytes)
type PathLimit struct {
	Path  string
	Limit int64
}

// AddMiddleware adds a middleware to a site's middleware stack.
func (s *SiteConfig) AddMiddleware(m Middleware) {
	s.middleware = append(s.middleware, m)
}

// AddListenerMiddleware adds a listener middleware to a site's listenerMiddleware stack.
func (s *SiteConfig) AddListenerMiddleware(l ListenerMiddleware) {
	s.listenerMiddleware = append(s.listenerMiddleware, l)
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

// ListenerMiddleware returns s.listenerMiddleware
func (s SiteConfig) ListenerMiddleware() []ListenerMiddleware {
	return s.listenerMiddleware
}
