package server

import (
	"errors"
	"log"
	"net/http"
	"os"

	"github.com/mholt/caddy/config"
	"github.com/mholt/caddy/middleware"
)

// servers maintains a registry of running servers.
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

	// Initialize
	s := new(Server)
	s.config = conf

	// Register the server
	servers[addr] = s

	return s, nil
}

// Serve starts the server. It blocks until the server quits.
func (s *Server) Serve() error {
	err := s.configureStack()
	if err != nil {
		return err
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

// configureStack builds the server's middleware stack based
// on its config. This method should be called last before
// ListenAndServe begins.
func (s *Server) configureStack() error {
	var mid []middleware.Middleware
	var err error
	conf := s.config

	// FileServer is the main application layer
	s.fileServer = http.FileServer(http.Dir(conf.Root))

	// push prepends each middleware to the stack so the
	// compilation can iterate them in a natural, increasing order
	push := func(m middleware.Middleware) {
		mid = append(mid, nil)
		copy(mid[1:], mid[0:])
		mid[0] = m
	}

	// BEGIN ADDING MIDDLEWARE
	// Middleware will be executed in the order they're added.

	if conf.RequestLog.Enabled {
		if conf.RequestLog.Enabled {
			s.reqlog, err = enableLogging(conf.RequestLog)
			if err != nil {
				return err
			}
		}
		push(middleware.RequestLog(s.reqlog, conf.RequestLog.Format))
	}

	if conf.ErrorLog.Enabled {
		if conf.ErrorLog.Enabled {
			s.errlog, err = enableLogging(conf.ErrorLog)
			if err != nil {
				return err
			}
		}
		push(middleware.ErrorLog(s.errlog, conf.ErrorLog.Format))
	}

	if len(conf.Rewrites) > 0 {
		push(middleware.Rewrite(conf.Rewrites))
	}

	if len(conf.Redirects) > 0 {
		push(middleware.Redirect(conf.Redirects))
	}

	if len(conf.Extensions) > 0 {
		push(middleware.Extensionless(conf.Root, conf.Extensions))
	}

	if len(conf.Headers) > 0 {
		push(middleware.Headers(conf.Headers))
	}

	if conf.Gzip {
		push(middleware.Gzip)
	}

	// END ADDING MIDDLEWARE

	// Compiling the middleware unwraps each HandlerFunc,
	// fully configured, ready to serve every request.
	s.compile(mid)

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

// enableLogging opens a log file and keeps it open for the lifetime
// of the server. In fact, the log file is never closed as long as
// the program is running, since the server will be running for
// that long. If that ever changes, the log file should be closed.
func enableLogging(l config.Log) (*log.Logger, error) {
	var file *os.File
	var err error

	if l.OutputFile == "stdout" {
		file = os.Stdout
	} else if l.OutputFile == "stderr" {
		file = os.Stderr
	} else {
		file, err = os.OpenFile(l.OutputFile, os.O_RDWR|os.O_CREATE|os.O_APPEND, 0666)
		if err != nil {
			return nil, err
		}
	}

	return log.New(file, "", 0), nil
}
