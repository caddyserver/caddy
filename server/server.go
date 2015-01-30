// Package server implements a configurable, general-purpose web server.
// It relies on configurations obtained from the adjacent config package
// and can execute middleware as defined by the adjacent middleware package.
package server

import (
	"errors"
	"log"
	"net/http"
	"runtime"

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
	reqlog     *log.Logger
	errlog     *log.Logger
	fileServer http.Handler
	stack      http.HandlerFunc
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
	err := s.buildStack()
	if err != nil {
		return err
	}

	if s.config.MaxCPU > 0 {
		runtime.GOMAXPROCS(s.config.MaxCPU)
	}

	if s.config.TLS.Enabled {
		return http.ListenAndServeTLS(s.config.Address(), s.config.TLS.Certificate, s.config.TLS.Key, s)
	} else {
		return http.ListenAndServe(s.config.Address(), s)
	}
}

// ServeHTTP is the entry point for each request to s.
func (s *Server) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	s.stack(w, r)
}

// Log writes a message to the server's configured error log,
// if there is one, or if there isn't, to the default stderr log.
func (s *Server) Log(v ...interface{}) {
	if s.errlog != nil {
		s.errlog.Println(v)
	} else {
		log.Println(v)
	}
}

// buildStack builds the server's middleware stack based
// on its config. This method should be called last before
// ListenAndServe begins.
func (s *Server) buildStack() error {
	s.fileServer = http.FileServer(http.Dir(s.config.Root))

	for _, start := range s.config.Startup {
		err := start()
		if err != nil {
			return err
		}
	}

	s.compile(s.config.Middleware)

	return nil
}

// compile is an elegant alternative to nesting middleware generator
// function calls like handler1(handler2(handler3(finalHandler))).
func (s *Server) compile(layers []middleware.Middleware) {
	s.stack = s.fileServer.ServeHTTP // core app layer
	for _, layer := range layers {
		s.stack = layer(s.stack)
	}
}
