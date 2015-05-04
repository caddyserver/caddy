package server

import (
	"net/http"

	"github.com/mholt/caddy/middleware"
)

// virtualHost represents a virtual host/server. While a Server
// is what actually binds to the address, a user may want to serve
// multiple sites on a single address, and this is what a
// virtualHost allows us to do.
type virtualHost struct {
	config     Config
	fileServer middleware.Handler
	stack      middleware.Handler
}

// buildStack builds the server's middleware stack based
// on its config. This method should be called last before
// ListenAndServe begins.
func (vh *virtualHost) buildStack() error {
	vh.fileServer = FileServer(http.Dir(vh.config.Root), []string{vh.config.ConfigFile})

	// TODO: We only compile middleware for the "/" scope.
	// Partial support for multiple location contexts already
	// exists at the parser and config levels, but until full
	// support is implemented, this is all we do right here.
	vh.compile(vh.config.Middleware["/"])

	return nil
}

// compile is an elegant alternative to nesting middleware function
// calls like handler1(handler2(handler3(finalHandler))).
func (vh *virtualHost) compile(layers []middleware.Middleware) {
	vh.stack = vh.fileServer // core app layer
	for i := len(layers) - 1; i >= 0; i-- {
		vh.stack = layers[i](vh.stack)
	}
}
