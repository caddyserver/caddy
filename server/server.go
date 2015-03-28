// Package server implements a configurable, general-purpose web server.
// It relies on configurations obtained from the adjacent config package
// and can execute middleware as defined by the adjacent middleware package.
package server

import (
	"errors"
	"log"
	"net/http"
	"os"
	"os/signal"
	"runtime"

	"github.com/bradfitz/http2"
	"github.com/mholt/caddy/config"
	"github.com/mholt/caddy/middleware"
)

// The default configuration file to load if none is specified
const DefaultConfigFile = "Caddyfile"

// servers maintains a registry of running servers, keyed by address.
var servers = make(map[string]*Server)

// Server represents an instance of a server, which serves
// static content at a particular address (host and port).
type Server struct {
	config     config.Config
	fileServer middleware.Handler
	stack      middleware.HandlerFunc
}

// New creates a new Server and registers it with the list
// of servers created. Each server must have a unique host:port
// combination. This function does not start serving.
func New(conf config.Config) (*Server, error) {
	addr := conf.Address()

	// Unique address check
	if _, exists := servers[addr]; exists {
		return nil, errors.New("Address " + addr + " is already in use")
	}

	// Use all CPUs (if needed) by default
	if conf.MaxCPU == 0 {
		conf.MaxCPU = runtime.NumCPU()
	}

	// Initialize
	s := new(Server)
	s.config = conf

	// Register the server
	servers[addr] = s

	return s, nil
}

// Serve starts the server. It blocks until the server quits.
func (s *Server) Serve() error {
	// Execute startup functions
	for _, start := range s.config.Startup {
		err := start()
		if err != nil {
			return err
		}
	}

	// Build middleware stack
	err := s.buildStack()
	if err != nil {
		return err
	}

	// Use highest procs value across all configurations
	if s.config.MaxCPU > 0 && s.config.MaxCPU > runtime.GOMAXPROCS(0) {
		runtime.GOMAXPROCS(s.config.MaxCPU)
	}

	server := &http.Server{
		Addr:    s.config.Address(),
		Handler: s,
	}

	// TODO: This call may not be necessary after HTTP/2 is merged into std lib
	http2.ConfigureServer(server, nil)

	// Execute shutdown commands on exit
	go func() {
		interrupt := make(chan os.Signal, 1)
		signal.Notify(interrupt, os.Interrupt, os.Kill) // TODO: syscall.SIGQUIT? (Ctrl+\, Unix-only)
		<-interrupt
		for _, shutdownFunc := range s.config.Shutdown {
			err := shutdownFunc()
			if err != nil {
				log.Fatal(err)
			}
		}
		os.Exit(0)
	}()

	if s.config.TLS.Enabled {
		return server.ListenAndServeTLS(s.config.TLS.Certificate, s.config.TLS.Key)
	} else {
		return server.ListenAndServe()
	}
}

// ServeHTTP is the entry point for every request to s.
func (s *Server) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	defer func() {
		// In case the user doesn't enable error middleware, we still
		// need to make sure that we stay alive up here
		if rec := recover(); rec != nil {
			http.Error(w, http.StatusText(http.StatusInternalServerError),
				http.StatusInternalServerError)
		}
	}()
	s.stack(w, r)
}

// buildStack builds the server's middleware stack based
// on its config. This method should be called last before
// ListenAndServe begins.
func (s *Server) buildStack() error {
	s.fileServer = FileServer(http.Dir(s.config.Root))

	// TODO: We only compile middleware for the "/" scope.
	// Partial support for multiple location contexts already
	// exists at the parser and config levels, but until full
	// support is implemented, this is all we do right here.
	s.compile(s.config.Middleware["/"])

	return nil
}

// compile is an elegant alternative to nesting middleware function
// calls like handler1(handler2(handler3(finalHandler))).
func (s *Server) compile(layers []middleware.Middleware) {
	s.stack = s.fileServer.ServeHTTP // core app layer
	for i := len(layers) - 1; i >= 0; i-- {
		s.stack = layers[i](s.stack)
	}
}
