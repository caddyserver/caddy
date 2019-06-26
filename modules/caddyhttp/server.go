package caddyhttp

import (
	"context"
	"fmt"
	"log"
	"net"
	"net/http"
	"strconv"

	"github.com/caddyserver/caddy"
	"github.com/caddyserver/caddy/modules/caddytls"
)

// Server is an HTTP server.
type Server struct {
	Listen            []string                    `json:"listen,omitempty"`
	ReadTimeout       caddy.Duration              `json:"read_timeout,omitempty"`
	ReadHeaderTimeout caddy.Duration              `json:"read_header_timeout,omitempty"`
	WriteTimeout      caddy.Duration              `json:"write_timeout,omitempty"`
	IdleTimeout       caddy.Duration              `json:"idle_timeout,omitempty"`
	MaxHeaderBytes    int                         `json:"max_header_bytes,omitempty"`
	Routes            RouteList                   `json:"routes,omitempty"`
	Errors            *HTTPErrorConfig            `json:"errors,omitempty"`
	TLSConnPolicies   caddytls.ConnectionPolicies `json:"tls_connection_policies,omitempty"`
	AutoHTTPS         *AutoHTTPSConfig            `json:"automatic_https,omitempty"`
	MaxRehandles      int                         `json:"max_rehandles,omitempty"`

	tlsApp *caddytls.TLS
}

// ServeHTTP is the entry point for all HTTP requests.
func (s *Server) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if s.tlsApp.HandleHTTPChallenge(w, r) {
		return
	}

	// set up the context for the request
	repl := caddy.NewReplacer()
	ctx := context.WithValue(r.Context(), caddy.ReplacerCtxKey, repl)
	ctx = context.WithValue(ctx, ServerCtxKey, s)
	ctx = context.WithValue(ctx, TableCtxKey, make(map[string]interface{})) // TODO: Implement this
	r = r.WithContext(ctx)

	// once the pointer to the request won't change
	// anymore, finish setting up the replacer
	addHTTPVarsToReplacer(repl, r, w)

	// build and execute the main handler chain
	stack, w := s.Routes.BuildCompositeRoute(w, r)
	err := s.executeCompositeRoute(w, r, stack)
	if err != nil {
		// add the raw error value to the request context
		// so it can be accessed by error handlers
		c := context.WithValue(r.Context(), ErrorCtxKey, err)
		r = r.WithContext(c)

		// add error values to the replacer
		repl.Set("http.error", err.Error())
		if handlerErr, ok := err.(HandlerError); ok {
			repl.Set("http.error.status_code", strconv.Itoa(handlerErr.StatusCode))
			repl.Set("http.error.status_text", http.StatusText(handlerErr.StatusCode))
			repl.Set("http.error.message", handlerErr.Message)
			repl.Set("http.error.trace", handlerErr.Trace)
			repl.Set("http.error.id", handlerErr.ID)
		}

		if s.Errors != nil && len(s.Errors.Routes) > 0 {
			errStack, w := s.Errors.Routes.BuildCompositeRoute(w, r)
			err := s.executeCompositeRoute(w, r, errStack)
			if err != nil {
				// TODO: what should we do if the error handler has an error?
				log.Printf("[ERROR] [%s %s] handling error: %v", r.Method, r.RequestURI, err)
			}
		} else {
			// TODO: polish the default error handling
			log.Printf("[ERROR] [%s %s] %v", r.Method, r.RequestURI, err)
			if handlerErr, ok := err.(HandlerError); ok {
				w.WriteHeader(handlerErr.StatusCode)
			} else {
				w.WriteHeader(http.StatusInternalServerError)
			}
		}
	}
}

// executeCompositeRoute executes stack with w and r. This function handles
// the special ErrRehandle error value, which reprocesses requests through
// the stack again. Any error value returned from this function would be an
// actual error that needs to be handled.
func (s *Server) executeCompositeRoute(w http.ResponseWriter, r *http.Request, stack Handler) error {
	var err error
	for i := -1; i <= s.MaxRehandles; i++ {
		// we started the counter at -1 because we
		// always want to run this at least once
		err = stack.ServeHTTP(w, r)
		if err != ErrRehandle {
			break
		}
		if i >= s.MaxRehandles-1 {
			return fmt.Errorf("too many rehandles")
		}
	}
	return err
}

func (s *Server) listenersUseAnyPortOtherThan(otherPort int) bool {
	for _, lnAddr := range s.Listen {
		_, addrs, err := parseListenAddr(lnAddr)
		if err == nil {
			for _, a := range addrs {
				_, port, err := net.SplitHostPort(a)
				if err == nil && port != strconv.Itoa(otherPort) {
					return true
				}
			}
		}
	}
	return false
}

// AutoHTTPSConfig is used to disable automatic HTTPS
// or certain aspects of it for a specific server.
type AutoHTTPSConfig struct {
	// If true, automatic HTTPS will be entirely disabled.
	Disabled bool `json:"disable,omitempty"`

	// If true, only automatic HTTP->HTTPS redirects will
	// be disabled.
	DisableRedir bool `json:"disable_redirects,omitempty"`

	// Hosts/domain names listed here will not be included
	// in automatic HTTPS (they will not have certificates
	// loaded nor redirects applied).
	Skip []string `json:"skip,omitempty"`
}

// HostSkipped returns true if name is supposed to be skipped
// when setting up automatic HTTPS.
func (ahc AutoHTTPSConfig) HostSkipped(name string) bool {
	for _, n := range ahc.Skip {
		if name == n {
			return true
		}
	}
	return false
}

// HTTPErrorConfig determines how to handle errors
// from the HTTP handlers.
type HTTPErrorConfig struct {
	Routes RouteList `json:"routes,omitempty"`
}

// Context keys for HTTP request context values.
const (
	// For referencing the server instance
	ServerCtxKey caddy.CtxKey = "server"

	// For the request's variable table (TODO: implement this)
	TableCtxKey caddy.CtxKey = "table"
)
