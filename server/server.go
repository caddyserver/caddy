// Package server implements a configurable, general-purpose web server.
// It relies on configurations obtained from the adjacent config package
// and can execute middleware as defined by the adjacent middleware package.
package server

import (
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"io/ioutil"
	"log"
	"net"
	"net/http"
	"os"
	"runtime"
	"sync"
	"time"
)

// Server represents an instance of a server, which serves
// HTTP requests at a particular address (host and port). A
// server is capable of serving numerous virtual hosts on
// the same address and the listener may be stopped for
// graceful termination (POSIX only).
type Server struct {
	*http.Server
	HTTP2       bool                   // whether to enable HTTP/2
	tls         bool                   // whether this server is serving all HTTPS hosts or not
	OnDemandTLS bool                   // whether this server supports on-demand TLS (load certs at handshake-time)
	vhosts      map[string]virtualHost // virtual hosts keyed by their address
	listener    ListenerFile           // the listener which is bound to the socket
	listenerMu  sync.Mutex             // protects listener
	httpWg      sync.WaitGroup         // used to wait on outstanding connections
	startChan   chan struct{}          // used to block until server is finished starting
	connTimeout time.Duration          // the maximum duration of a graceful shutdown
	ReqCallback OptionalCallback       // if non-nil, is executed at the beginning of every request
	SNICallback func(clientHello *tls.ClientHelloInfo) (*tls.Certificate, error)
}

// ListenerFile represents a listener.
type ListenerFile interface {
	net.Listener
	File() (*os.File, error)
}

// OptionalCallback is a function that may or may not handle a request.
// It returns whether or not it handled the request. If it handled the
// request, it is presumed that no further request handling should occur.
type OptionalCallback func(http.ResponseWriter, *http.Request) bool

// New creates a new Server which will bind to addr and serve
// the sites/hosts configured in configs. Its listener will
// gracefully close when the server is stopped which will take
// no longer than gracefulTimeout.
//
// This function does not start serving.
//
// Do not re-use a server (start, stop, then start again). We
// could probably add more locking to make this possible, but
// as it stands, you should dispose of a server after stopping it.
// The behavior of serving with a spent server is undefined.
func New(addr string, configs []Config, gracefulTimeout time.Duration) (*Server, error) {
	var useTLS, useOnDemandTLS bool
	if len(configs) > 0 {
		useTLS = configs[0].TLS.Enabled
		useOnDemandTLS = configs[0].TLS.OnDemand
	}

	s := &Server{
		Server: &http.Server{
			Addr:      addr,
			TLSConfig: new(tls.Config),
			// TODO: Make these values configurable?
			// ReadTimeout:    2 * time.Minute,
			// WriteTimeout:   2 * time.Minute,
			// MaxHeaderBytes: 1 << 16,
		},
		tls:         useTLS,
		OnDemandTLS: useOnDemandTLS,
		vhosts:      make(map[string]virtualHost),
		startChan:   make(chan struct{}),
		connTimeout: gracefulTimeout,
	}
	s.Handler = s // this is weird, but whatever

	// We have to bound our wg with one increment
	// to prevent a "race condition" that is hard-coded
	// into sync.WaitGroup.Wait() - basically, an add
	// with a positive delta must be guaranteed to
	// occur before Wait() is called on the wg.
	// In a way, this kind of acts as a safety barrier.
	s.httpWg.Add(1)

	// Set up each virtualhost
	for _, conf := range configs {
		if _, exists := s.vhosts[conf.Host]; exists {
			return nil, fmt.Errorf("cannot serve %s - host already defined for address %s", conf.Address(), s.Addr)
		}

		vh := virtualHost{config: conf}

		// Build middleware stack
		err := vh.buildStack()
		if err != nil {
			return nil, err
		}

		s.vhosts[conf.Host] = vh
	}

	return s, nil
}

// Serve starts the server with an existing listener. It blocks until the
// server stops.
func (s *Server) Serve(ln ListenerFile) error {
	err := s.setup()
	if err != nil {
		defer close(s.startChan) // MUST defer so error is properly reported, same with all cases in this file
		return err
	}
	return s.serve(ln)
}

// ListenAndServe starts the server with a new listener. It blocks until the server stops.
func (s *Server) ListenAndServe() error {
	err := s.setup()
	if err != nil {
		defer close(s.startChan)
		return err
	}

	ln, err := net.Listen("tcp", s.Addr)
	if err != nil {
		var succeeded bool
		if runtime.GOOS == "windows" { // TODO: Limit this to Windows only? (it keeps sockets open after closing listeners)
			for i := 0; i < 20; i++ {
				time.Sleep(100 * time.Millisecond)
				ln, err = net.Listen("tcp", s.Addr)
				if err == nil {
					succeeded = true
					break
				}
			}
		}
		if !succeeded {
			defer close(s.startChan)
			return err
		}
	}

	return s.serve(ln.(*net.TCPListener))
}

// serve prepares s to listen on ln by wrapping ln in a
// tcpKeepAliveListener (if ln is a *net.TCPListener) and
// then in a gracefulListener, so that keep-alive is supported
// as well as graceful shutdown/restart. It also configures
// TLS listener on top of that if applicable.
func (s *Server) serve(ln ListenerFile) error {
	if tcpLn, ok := ln.(*net.TCPListener); ok {
		ln = tcpKeepAliveListener{TCPListener: tcpLn}
	}

	s.listenerMu.Lock()
	s.listener = newGracefulListener(ln, &s.httpWg)
	s.listenerMu.Unlock()

	if s.tls {
		var tlsConfigs []TLSConfig
		for _, vh := range s.vhosts {
			tlsConfigs = append(tlsConfigs, vh.config.TLS)
		}
		return serveTLS(s, s.listener, tlsConfigs)
	}

	close(s.startChan) // unblock anyone waiting for this to start listening
	return s.Server.Serve(s.listener)
}

// setup prepares the server s to begin listening; it should be
// called just before the listener announces itself on the network
// and should only be called when the server is just starting up.
func (s *Server) setup() error {
	if !s.HTTP2 {
		s.TLSNextProto = make(map[string]func(*http.Server, *tls.Conn, http.Handler))
	}

	// Execute startup functions now
	for _, vh := range s.vhosts {
		for _, startupFunc := range vh.config.Startup {
			err := startupFunc()
			if err != nil {
				return err
			}
		}
	}

	return nil
}

// serveTLS serves TLS with SNI and client auth support if s has them enabled. It
// blocks until s quits.
func serveTLS(s *Server, ln net.Listener, tlsConfigs []TLSConfig) error {
	// Customize our TLS configuration
	s.TLSConfig.MinVersion = tlsConfigs[0].ProtocolMinVersion
	s.TLSConfig.MaxVersion = tlsConfigs[0].ProtocolMaxVersion
	s.TLSConfig.CipherSuites = tlsConfigs[0].Ciphers
	s.TLSConfig.PreferServerCipherSuites = tlsConfigs[0].PreferServerCipherSuites

	// TLS client authentication, if user enabled it
	err := setupClientAuth(tlsConfigs, s.TLSConfig)
	if err != nil {
		defer close(s.startChan)
		return err
	}

	// Create TLS listener - note that we do not replace s.listener
	// with this TLS listener; tls.listener is unexported and does
	// not implement the File() method we need for graceful restarts
	// on POSIX systems.
	ln = tls.NewListener(ln, s.TLSConfig)

	close(s.startChan) // unblock anyone waiting for this to start listening
	return s.Server.Serve(ln)
}

// Stop stops the server. It blocks until the server is
// totally stopped. On POSIX systems, it will wait for
// connections to close (up to a max timeout of a few
// seconds); on Windows it will close the listener
// immediately.
func (s *Server) Stop() (err error) {
	s.Server.SetKeepAlivesEnabled(false)

	if runtime.GOOS != "windows" {
		// force connections to close after timeout
		done := make(chan struct{})
		go func() {
			s.httpWg.Done() // decrement our initial increment used as a barrier
			s.httpWg.Wait()
			close(done)
		}()

		// Wait for remaining connections to finish or
		// force them all to close after timeout
		select {
		case <-time.After(s.connTimeout):
		case <-done:
		}
	}

	// Close the listener now; this stops the server without delay
	s.listenerMu.Lock()
	if s.listener != nil {
		err = s.listener.Close()
	}
	s.listenerMu.Unlock()

	return
}

// WaitUntilStarted blocks until the server s is started, meaning
// that practically the next instruction is to start the server loop.
// It also unblocks if the server encounters an error during startup.
func (s *Server) WaitUntilStarted() {
	<-s.startChan
}

// ListenerFd gets a dup'ed file of the listener. If there
// is no underlying file, the return value will be nil. It
// is the caller's responsibility to close the file.
func (s *Server) ListenerFd() *os.File {
	s.listenerMu.Lock()
	defer s.listenerMu.Unlock()
	if s.listener != nil {
		file, _ := s.listener.File()
		return file
	}
	return nil
}

// ServeHTTP is the entry point for every request to the address that s
// is bound to. It acts as a multiplexer for the requests hostname as
// defined in the Host header so that the correct virtualhost
// (configuration and middleware stack) will handle the request.
func (s *Server) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	defer func() {
		// In case the user doesn't enable error middleware, we still
		// need to make sure that we stay alive up here
		if rec := recover(); rec != nil {
			http.Error(w, http.StatusText(http.StatusInternalServerError),
				http.StatusInternalServerError)
		}
	}()

	w.Header().Set("Server", "Caddy")

	host, _, err := net.SplitHostPort(r.Host)
	if err != nil {
		host = r.Host // oh well
	}

	// Try the host as given, or try falling back to 0.0.0.0 (wildcard)
	if _, ok := s.vhosts[host]; !ok {
		if _, ok2 := s.vhosts["0.0.0.0"]; ok2 {
			host = "0.0.0.0"
		} else if _, ok2 := s.vhosts[""]; ok2 {
			host = ""
		}
	}

	// Execute the optional request callback if it exists and it's not disabled
	if s.ReqCallback != nil && !s.vhosts[host].config.TLS.Manual && s.ReqCallback(w, r) {
		return
	}

	if vh, ok := s.vhosts[host]; ok {
		status, _ := vh.stack.ServeHTTP(w, r)

		// Fallback error response in case error handling wasn't chained in
		if status >= 400 {
			DefaultErrorFunc(w, r, status)
		}
	} else {
		// Get the remote host
		remoteHost, _, err := net.SplitHostPort(r.RemoteAddr)
		if err != nil {
			remoteHost = r.RemoteAddr
		}

		w.WriteHeader(http.StatusNotFound)
		fmt.Fprintf(w, "No such host at %s", s.Server.Addr)
		log.Printf("[INFO] %s - No such host at %s (Remote: %s, Referer: %s)",
			host, s.Server.Addr, remoteHost, r.Header.Get("Referer"))
	}
}

// DefaultErrorFunc responds to an HTTP request with a simple description
// of the specified HTTP status code.
func DefaultErrorFunc(w http.ResponseWriter, r *http.Request, status int) {
	w.WriteHeader(status)
	fmt.Fprintf(w, "%d %s", status, http.StatusText(status))
}

// setupClientAuth sets up TLS client authentication only if
// any of the TLS configs specified at least one cert file.
func setupClientAuth(tlsConfigs []TLSConfig, config *tls.Config) error {
	var clientAuth bool
	for _, cfg := range tlsConfigs {
		if len(cfg.ClientCerts) > 0 {
			clientAuth = true
			break
		}
	}

	if clientAuth {
		pool := x509.NewCertPool()
		for _, cfg := range tlsConfigs {
			for _, caFile := range cfg.ClientCerts {
				caCrt, err := ioutil.ReadFile(caFile) // Anyone that gets a cert from this CA can connect
				if err != nil {
					return err
				}
				if !pool.AppendCertsFromPEM(caCrt) {
					return fmt.Errorf("error loading client certificate '%s': no certificates were successfully parsed", caFile)
				}
			}
		}
		config.ClientCAs = pool
		config.ClientAuth = tls.RequireAndVerifyClientCert
	}

	return nil
}

// RunFirstStartupFuncs runs all of the server's FirstStartup
// callback functions unless one of them returns an error first.
// It is the caller's responsibility to call this only once and
// at the correct time. The functions here should not be executed
// at restarts or where the user does not explicitly start a new
// instance of the server.
func (s *Server) RunFirstStartupFuncs() error {
	for _, vh := range s.vhosts {
		for _, f := range vh.config.FirstStartup {
			if err := f(); err != nil {
				return err
			}
		}
	}
	return nil
}

// tcpKeepAliveListener sets TCP keep-alive timeouts on accepted
// connections. It's used by ListenAndServe and ListenAndServeTLS so
// dead TCP connections (e.g. closing laptop mid-download) eventually
// go away.
//
// Borrowed from the Go standard library.
type tcpKeepAliveListener struct {
	*net.TCPListener
}

// Accept accepts the connection with a keep-alive enabled.
func (ln tcpKeepAliveListener) Accept() (c net.Conn, err error) {
	tc, err := ln.AcceptTCP()
	if err != nil {
		return
	}
	tc.SetKeepAlive(true)
	tc.SetKeepAlivePeriod(3 * time.Minute)
	return tc, nil
}

// File implements ListenerFile; returns the underlying file of the listener.
func (ln tcpKeepAliveListener) File() (*os.File, error) {
	return ln.TCPListener.File()
}

// ShutdownCallbacks executes all the shutdown callbacks
// for all the virtualhosts in servers, and returns all the
// errors generated during their execution. In other words,
// an error executing one shutdown callback does not stop
// execution of others. Only one shutdown callback is executed
// at a time. You must protect the servers that are passed in
// if they are shared across threads.
func ShutdownCallbacks(servers []*Server) []error {
	var errs []error
	for _, s := range servers {
		for _, vhost := range s.vhosts {
			for _, shutdownFunc := range vhost.config.Shutdown {
				err := shutdownFunc()
				if err != nil {
					errs = append(errs, err)
				}
			}
		}
	}
	return errs
}
