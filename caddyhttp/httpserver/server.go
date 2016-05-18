// Package httpserver implements an HTTP server on top of Caddy.
package httpserver

import (
	"crypto/tls"
	"fmt"
	"log"
	"net"
	"net/http"
	"os"
	"path"
	"runtime"
	"strings"
	"sync"
	"time"

	"github.com/mholt/caddy2/shared/caddytls"
)

type SiteConfig struct {
	// The address of the site
	Addr Address

	// The hostname to bind listener to;
	// defaults to Addr.Host
	ListenHost string

	// TLS configuration
	TLS *caddytls.Config

	// Middleware stack
	middleware []Middleware

	// Directory from which to serve files
	Root string
}

func (s SiteConfig) TLSConfig() *caddytls.Config {
	return s.TLS
}

func (s SiteConfig) Host() string {
	return s.Addr.Host
}

func (s SiteConfig) Port() string {
	return s.Addr.Port
}

// TODO: get useful comments on all these fields
type Server struct {
	*http.Server
	//tls         *caddytls.Config
	tls         bool
	listener    net.Listener
	listenerMu  sync.Mutex // TODO: How necessary is this?
	connTimeout time.Duration
	connWg      sync.WaitGroup
	tlsGovChan  chan struct{} // close to stop the TLS maintenance goroutine
	vhosts      *vhostTrie
}

func NewServer(addr string, group []*SiteConfig) (*Server, error) {
	s := &Server{
		Server: &http.Server{
			Addr: addr,
			// TODO: Make these values configurable?
			// ReadTimeout:    2 * time.Minute,
			// WriteTimeout:   2 * time.Minute,
			// MaxHeaderBytes: 1 << 16,
		},
		vhosts: newVHostTrie(),
	}
	s.Handler = s // this is weird, but whatever

	// We have to bound our wg with one increment
	// to prevent a "race condition" that is hard-coded
	// into sync.WaitGroup.Wait() - basically, an add
	// with a positive delta must be guaranteed to
	// occur before Wait() is called on the wg.
	// In a way, this kind of acts as a safety barrier.
	s.connWg.Add(1)

	// Set up TLS configuration
	var tlsConfigs []*caddytls.Config
	var err error
	for _, site := range group {
		tlsConfigs = append(tlsConfigs, site.TLS)
	}
	s.TLSConfig, err = caddytls.MakeTLSConfig(tlsConfigs)
	if err != nil {
		return nil, err
	}

	// Compile middleware stacks (configures virtual hosting)
	for _, site := range group {
		var stack Handler // TODO: file server
		for i := len(site.middleware) - 1; i >= 0; i-- {
			stack = site.middleware[i](stack)
		}
		s.vhosts.Insert(site.Addr.VHost(), stack)
	}

	return s, nil
}

func (s *Server) Listen() (net.Listener, error) {
	if s.Server == nil {
		return nil, fmt.Errorf("Server field is nil")
	}

	ln, err := net.Listen("tcp", s.Addr)
	if err != nil {
		var succeeded bool
		if runtime.GOOS == "windows" {
			// Windows has been known to keep sockets open even after closing the listeners.
			// Tests reveal this error case easily because they call Start() then Stop()
			// in succession. TODO: Better way to handle this? And why limit this to Windows?
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
			return nil, err
		}
	}

	// Very important to return a concrete caddy.Listener
	// implementation for graceful restarts.
	return ln.(*net.TCPListener), nil
}

func (s *Server) Serve(ln net.Listener) error {
	if tcpLn, ok := ln.(*net.TCPListener); ok {
		ln = tcpKeepAliveListener{TCPListener: tcpLn}
	}

	ln = newGracefulListener(ln, &s.connWg)

	s.listenerMu.Lock()
	s.listener = ln
	s.listenerMu.Unlock()

	if s.TLSConfig != nil {
		// Create TLS listener - note that we do not replace s.listener
		// with this TLS listener; tls.listener is unexported and does
		// not implement the File() method we need for graceful restarts
		// on POSIX systems.
		// TODO: Is this ^ still relevant anymore? Maybe we can now that it's a net.Listener...
		ln = tls.NewListener(ln, s.TLSConfig)
	}

	return s.Server.Serve(ln)
}

func (s *Server) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	defer func() {
		// We absolutely need to be sure we stay alive up here,
		// even though in theory the errors middleware does this.
		if rec := recover(); rec != nil {
			http.Error(w, http.StatusText(http.StatusInternalServerError),
				http.StatusInternalServerError)
		}
	}()

	w.Header().Set("Server", "Caddy")

	// TODO: This is temporary
	//fmt.Fprintf(w, "PID %d\n", os.Getpid())

	// Collapse any ./ ../ /// madness right away. Note to middleware:
	// use URL.RawPath If you need the "original" URL.Path value.
	if r.URL.Path != "/" {
		cleanedPath := path.Clean(r.URL.Path)
		if cleanedPath == "." {
			r.URL.Path = "/"
		} else {
			if !strings.HasPrefix(cleanedPath, "/") {
				cleanedPath = "/" + cleanedPath
			}
			if strings.HasSuffix(r.URL.Path, "/") && !strings.HasSuffix(cleanedPath, "/") {
				cleanedPath = cleanedPath + "/"
			}
			r.URL.Path = cleanedPath
		}
	}

	// strip out the port because it's not used in virtual
	// hosting, the port is irrelevant because each listener
	// is on a different port.
	hostname, _, err := net.SplitHostPort(r.Host)
	if err != nil {
		hostname = r.Host
	}

	vhost := s.vhosts.Match(hostname + r.URL.Path)

	if vhost == nil {
		remoteHost, _, err := net.SplitHostPort(r.RemoteAddr)
		if err != nil {
			remoteHost = r.RemoteAddr
		}
		w.WriteHeader(http.StatusNotFound)
		fmt.Fprintf(w, "No such site at %s", s.Server.Addr)
		log.Printf("[INFO] %s - No such site at %s (Remote: %s, Referer: %s)",
			hostname, s.Server.Addr, remoteHost, r.Header.Get("Referer"))
		return
	}

	status, _ := vhost.ServeHTTP(w, r)

	// Fallback error response in case error handling wasn't chained in
	if status >= 400 {
		DefaultErrorFunc(w, r, status)
	}

	/*
		host, _, err := net.SplitHostPort(r.Host)
		if err != nil {
			host = r.Host // oh well
		}

		// "The host subcomponent is case-insensitive." (RFC 3986)
		host = strings.ToLower(host)

		// Try the host as given, or try falling back to 0.0.0.0 (wildcard)
		if _, ok := s.vhosts[host]; !ok {
			if _, ok2 := s.vhosts["0.0.0.0"]; ok2 {
				host = "0.0.0.0"
			} else if _, ok2 := s.vhosts[""]; ok2 {
				host = ""
			}
		}

		// Use URL.RawPath If you need the original, "raw" URL.Path in your middleware.
		// Collapse any ./ ../ /// madness here instead of doing that in every plugin.
		if r.URL.Path != "/" {
			cleanedPath := path.Clean(r.URL.Path)
			if cleanedPath == "." {
				r.URL.Path = "/"
			} else {
				if !strings.HasPrefix(cleanedPath, "/") {
					cleanedPath = "/" + cleanedPath
				}
				if strings.HasSuffix(r.URL.Path, "/") && !strings.HasSuffix(cleanedPath, "/") {
					cleanedPath = cleanedPath + "/"
				}
				r.URL.Path = cleanedPath
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
	*/
}

func (s *Server) Address() string {
	return s.Server.Addr
}

func (s *Server) Stop() (err error) {
	s.SetKeepAlivesEnabled(false)

	if runtime.GOOS != "windows" {
		// force connections to close after timeout
		done := make(chan struct{})
		go func() {
			s.connWg.Done() // decrement our initial increment used as a barrier
			s.connWg.Wait()
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

	// Closing this signals any TLS governor goroutines to exit
	if s.tlsGovChan != nil {
		close(s.tlsGovChan)
	}

	return
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

// File implements caddy.Listener; it returns the underlying file of the listener.
func (ln tcpKeepAliveListener) File() (*os.File, error) {
	return ln.TCPListener.File()
}

// DefaultErrorFunc responds to an HTTP request with a simple description
// of the specified HTTP status code.
func DefaultErrorFunc(w http.ResponseWriter, r *http.Request, status int) {
	w.WriteHeader(status)
	fmt.Fprintf(w, "%d %s", status, http.StatusText(status))
}
