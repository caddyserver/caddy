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

	"github.com/lucas-clemente/quic-go/h2quic"
	"github.com/mholt/caddy"
	"github.com/mholt/caddy/caddyhttp/staticfiles"
	"github.com/mholt/caddy/caddytls"
)

// Server is the HTTP server implementation.
type Server struct {
	Server      *http.Server
	quicServer  *h2quic.Server
	listener    net.Listener
	listenerMu  sync.Mutex
	sites       []*SiteConfig
	connTimeout time.Duration  // max time to wait for a connection before force stop
	connWg      sync.WaitGroup // one increment per connection
	tlsGovChan  chan struct{}  // close to stop the TLS maintenance goroutine
	vhosts      *vhostTrie
}

// ensure it satisfies the interface
var _ caddy.GracefulServer = new(Server)

// NewServer creates a new Server instance that will listen on addr
// and will serve the sites configured in group.
func NewServer(addr string, group []*SiteConfig) (*Server, error) {
	s := &Server{
		Server: &http.Server{
			Addr: addr,
			// TODO: Make these values configurable?
			// ReadTimeout:    2 * time.Minute,
			// WriteTimeout:   2 * time.Minute,
			// MaxHeaderBytes: 1 << 16,
		},
		vhosts:      newVHostTrie(),
		sites:       group,
		connTimeout: GracefulTimeout,
	}
	s.Server.Handler = s // this is weird, but whatever
	s.Server.ConnState = func(c net.Conn, cs http.ConnState) {
		if cs == http.StateIdle {
			s.listenerMu.Lock()
			// server stopped, close idle connection
			if s.listener == nil {
				c.Close()
			}
			s.listenerMu.Unlock()
		}
	}

	// Disable HTTP/2 if desired
	if !HTTP2 {
		s.Server.TLSNextProto = make(map[string]func(*http.Server, *tls.Conn, http.Handler))
	}

	// Enable QUIC if desired
	if QUIC {
		s.quicServer = &h2quic.Server{Server: s.Server}
		s.Server.Handler = s.wrapWithSvcHeaders(s.Server.Handler)
	}

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
	s.Server.TLSConfig, err = caddytls.MakeTLSConfig(tlsConfigs)
	if err != nil {
		return nil, err
	}
	// Since Go 1.7 HTTP/2 is enabled only if TLSConfig.NextProtos includes the string "h2".
	if HTTP2 && s.Server.TLSConfig != nil && len(s.Server.TLSConfig.NextProtos) == 0 {
		s.Server.TLSConfig.NextProtos = []string{"h2"}
	}

	// Compile custom middleware for every site (enables virtual hosting)
	for _, site := range group {
		stack := Handler(staticfiles.FileServer{Root: http.Dir(site.Root), Hide: site.HiddenFiles})
		for i := len(site.middleware) - 1; i >= 0; i-- {
			stack = site.middleware[i](stack)
		}
		site.middlewareChain = stack
		s.vhosts.Insert(site.Addr.VHost(), site)
	}

	return s, nil
}

func (s *Server) wrapWithSvcHeaders(previousHandler http.Handler) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		s.quicServer.SetQuicHeaders(w.Header())
		previousHandler.ServeHTTP(w, r)
	}
}

// Listen creates an active listener for s that can be
// used to serve requests.
func (s *Server) Listen() (net.Listener, error) {
	if s.Server == nil {
		return nil, fmt.Errorf("Server field is nil")
	}

	ln, err := net.Listen("tcp", s.Server.Addr)
	if err != nil {
		var succeeded bool
		if runtime.GOOS == "windows" {
			// Windows has been known to keep sockets open even after closing the listeners.
			// Tests reveal this error case easily because they call Start() then Stop()
			// in succession. TODO: Better way to handle this? And why limit this to Windows?
			for i := 0; i < 20; i++ {
				time.Sleep(100 * time.Millisecond)
				ln, err = net.Listen("tcp", s.Server.Addr)
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

// ListenPacket is a noop to implement the Server interface.
func (s *Server) ListenPacket() (net.PacketConn, error) { return nil, nil }

// Serve serves requests on ln. It blocks until ln is closed.
func (s *Server) Serve(ln net.Listener) error {
	if tcpLn, ok := ln.(*net.TCPListener); ok {
		ln = tcpKeepAliveListener{TCPListener: tcpLn}
	}

	ln = newGracefulListener(ln, &s.connWg)

	s.listenerMu.Lock()
	s.listener = ln
	s.listenerMu.Unlock()

	if s.Server.TLSConfig != nil {
		// Create TLS listener - note that we do not replace s.listener
		// with this TLS listener; tls.listener is unexported and does
		// not implement the File() method we need for graceful restarts
		// on POSIX systems.
		// TODO: Is this ^ still relevant anymore? Maybe we can now that it's a net.Listener...
		ln = tls.NewListener(ln, s.Server.TLSConfig)

		// Rotate TLS session ticket keys
		s.tlsGovChan = caddytls.RotateSessionTicketKeys(s.Server.TLSConfig)
	}

	if QUIC {
		go func() {
			err := s.quicServer.ListenAndServe()
			if err != nil {
				log.Printf("[ERROR] listening for QUIC connections: %v", err)
			}
		}()
	}

	err := s.Server.Serve(ln)
	if QUIC {
		s.quicServer.Close()
	}
	return err
}

// ServePacket is a noop to implement the Server interface.
func (s *Server) ServePacket(pc net.PacketConn) error { return nil }

// ServeHTTP is the entry point of all HTTP requests.
func (s *Server) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	defer func() {
		// We absolutely need to be sure we stay alive up here,
		// even though, in theory, the errors middleware does this.
		if rec := recover(); rec != nil {
			log.Printf("[PANIC] %v", rec)
			DefaultErrorFunc(w, r, http.StatusInternalServerError)
		}
	}()

	w.Header().Set("Server", "Caddy")

	sanitizePath(r)

	status, _ := s.serveHTTP(w, r)

	// Fallback error response in case error handling wasn't chained in
	if status >= 400 {
		DefaultErrorFunc(w, r, status)
	}
}

func (s *Server) serveHTTP(w http.ResponseWriter, r *http.Request) (int, error) {
	// strip out the port because it's not used in virtual
	// hosting; the port is irrelevant because each listener
	// is on a different port.
	hostname, _, err := net.SplitHostPort(r.Host)
	if err != nil {
		hostname = r.Host
	}

	// look up the virtualhost; if no match, serve error
	vhost, pathPrefix := s.vhosts.Match(hostname + r.URL.Path)

	if vhost == nil {
		// check for ACME challenge even if vhost is nil;
		// could be a new host coming online soon
		if caddytls.HTTPChallengeHandler(w, r, caddytls.DefaultHTTPAlternatePort) {
			return 0, nil
		}
		// otherwise, log the error and write a message to the client
		remoteHost, _, err := net.SplitHostPort(r.RemoteAddr)
		if err != nil {
			remoteHost = r.RemoteAddr
		}
		WriteTextResponse(w, http.StatusNotFound, "No such site at "+s.Server.Addr)
		log.Printf("[INFO] %s - No such site at %s (Remote: %s, Referer: %s)",
			hostname, s.Server.Addr, remoteHost, r.Header.Get("Referer"))
		return 0, nil
	}

	// we still check for ACME challenge if the vhost exists,
	// because we must apply its HTTP challenge config settings
	if s.proxyHTTPChallenge(vhost, w, r) {
		return 0, nil
	}

	// trim the path portion of the site address from the beginning of
	// the URL path, so a request to example.com/foo/blog on the site
	// defined as example.com/foo appears as /blog instead of /foo/blog.
	if pathPrefix != "/" {
		r.URL.Path = strings.TrimPrefix(r.URL.Path, pathPrefix)
		if !strings.HasPrefix(r.URL.Path, "/") {
			r.URL.Path = "/" + r.URL.Path
		}
	}

	return vhost.middlewareChain.ServeHTTP(w, r)
}

// proxyHTTPChallenge solves the ACME HTTP challenge if r is the HTTP
// request for the challenge. If it is, and if the request has been
// fulfilled (response written), true is returned; false otherwise.
// If you don't have a vhost, just call the challenge handler directly.
func (s *Server) proxyHTTPChallenge(vhost *SiteConfig, w http.ResponseWriter, r *http.Request) bool {
	if vhost.Addr.Port != caddytls.HTTPChallengePort {
		return false
	}
	if vhost.TLS != nil && vhost.TLS.Manual {
		return false
	}
	altPort := caddytls.DefaultHTTPAlternatePort
	if vhost.TLS != nil && vhost.TLS.AltHTTPPort != "" {
		altPort = vhost.TLS.AltHTTPPort
	}
	return caddytls.HTTPChallengeHandler(w, r, altPort)
}

// Address returns the address s was assigned to listen on.
func (s *Server) Address() string {
	return s.Server.Addr
}

// Stop stops s gracefully (or forcefully after timeout) and
// closes its listener.
func (s *Server) Stop() (err error) {
	s.Server.SetKeepAlivesEnabled(false)

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
		s.listener = nil
	}
	s.listenerMu.Unlock()

	// Closing this signals any TLS governor goroutines to exit
	if s.tlsGovChan != nil {
		close(s.tlsGovChan)
	}

	return
}

// sanitizePath collapses any ./ ../ /// madness
// which helps prevent path traversal attacks.
// Note to middleware: use URL.RawPath If you need
// the "original" URL.Path value.
func sanitizePath(r *http.Request) {
	if r.URL.Path == "/" {
		return
	}
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

// OnStartupComplete lists the sites served by this server
// and any relevant information, assuming caddy.Quiet == false.
func (s *Server) OnStartupComplete() {
	if caddy.Quiet {
		return
	}
	for _, site := range s.sites {
		output := site.Addr.String()
		if caddy.IsLoopback(s.Address()) && !caddy.IsLoopback(site.Addr.Host) {
			output += " (only accessible on this machine)"
		}
		fmt.Println(output)
	}
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
	WriteTextResponse(w, status, fmt.Sprintf("%d %s\n", status, http.StatusText(status)))
}

// WriteTextResponse writes body with code status to w. The body will
// be interpreted as plain text.
func WriteTextResponse(w http.ResponseWriter, status int, body string) {
	w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	w.Header().Set("X-Content-Type-Options", "nosniff")
	w.WriteHeader(status)
	w.Write([]byte(body))
}
