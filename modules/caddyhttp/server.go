package caddyhttp

import (
	"context"
	"fmt"
	"log"
	"net/http"
	"strconv"

	"bitbucket.org/lightcodelabs/caddy2"
	"bitbucket.org/lightcodelabs/caddy2/modules/caddytls"
)

// Server is an HTTP server.
type Server struct {
	Listen                []string                    `json:"listen"`
	ReadTimeout           caddy2.Duration             `json:"read_timeout"`
	ReadHeaderTimeout     caddy2.Duration             `json:"read_header_timeout"`
	Routes                RouteList                   `json:"routes"`
	Errors                httpErrorConfig             `json:"errors"`
	TLSConnPolicies       caddytls.ConnectionPolicies `json:"tls_connection_policies"`
	DisableAutoHTTPS      bool                        `json:"disable_auto_https"`
	DisableAutoHTTPSRedir bool                        `json:"disable_auto_https_redir"`
	MaxRehandles          int                         `json:"max_rehandles"`

	tlsApp *caddytls.TLS
}

// ServeHTTP is the entry point for all HTTP requests.
func (s *Server) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if s.tlsApp.HandleHTTPChallenge(w, r) {
		return
	}

	// set up the replacer
	repl := newReplacer(r, w)
	ctx := context.WithValue(r.Context(), caddy2.ReplacerCtxKey, repl)
	ctx = context.WithValue(ctx, TableCtxKey, make(map[string]interface{})) // TODO: Implement this
	r = r.WithContext(ctx)

	// build and execute the main handler chain
	stack := s.Routes.BuildCompositeRoute(w, r)
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

		if len(s.Errors.Routes) == 0 {
			// TODO: polish the default error handling
			log.Printf("[ERROR] Handler: %s", err)
			if handlerErr, ok := err.(HandlerError); ok {
				w.WriteHeader(handlerErr.StatusCode)
			}
		} else {
			errStack := s.Errors.Routes.BuildCompositeRoute(w, r)
			err := s.executeCompositeRoute(w, r, errStack)
			if err != nil {
				// TODO: what should we do if the error handler has an error?
				log.Printf("[ERROR] handling error: %v", err)
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

type httpErrorConfig struct {
	Routes RouteList `json:"routes"`
	// TODO: some way to configure the logging of errors, probably? standardize
	// the logging configuration first.
}

// TableCtxKey is the context key for the request's variable table.
const TableCtxKey caddy2.CtxKey = "table"
