// Package httpserver implements an HTTP server on top of Caddy.
package httpserver

import (
	"crypto/tls"
	"errors"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"os"
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
	mu          sync.Mutex
	sites       []*SiteConfig
	closed      bool
	connTimeout time.Duration               // max time to wait for a connection before force stop
	connWg      *sync.WaitGroup             // one increment per connection
	conns       map[net.Conn]http.ConnState // store idle connections
	tlsGovChan  chan struct{}               // close to stop the TLS maintenance goroutine
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
		connWg:      &sync.WaitGroup{},
	}
	s.Server.Handler = s // this is weird, but whatever

	// Track connection state
	s.connState()

	// Disable HTTP/2 if desired
	if !HTTP2 {
		s.Server.TLSNextProto = make(map[string]func(*http.Server, *tls.Conn, http.Handler))
	}

	// Enable QUIC if desired
	if QUIC {
		s.quicServer = &h2quic.Server{Server: s.Server}
		s.Server.Handler = s.wrapWithSvcHeaders(s.Server.Handler)
	}

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

	// As of Go 1.7, HTTP/2 is enabled only if NextProtos includes the string "h2"
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

	s.listener = ln

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
		if caddytls.HTTPChallengeHandler(w, r, "localhost", caddytls.DefaultHTTPAlternatePort) {
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

	// Apply the path-based request body size limit
	// The error returned by MaxBytesReader is meant to be handled
	// by whichever middleware/plugin that receives it when calling
	// .Read() or a similar method on the request body
	if r.Body != nil {
		for _, pathlimit := range vhost.MaxRequestBodySizes {
			if Path(r.URL.Path).Matches(pathlimit.Path) {
				r.Body = MaxBytesReader(w, r.Body, pathlimit.Limit)
				break
			}
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
	return caddytls.HTTPChallengeHandler(w, r, vhost.ListenHost, altPort)
}

// Address returns the address s was assigned to listen on.
func (s *Server) Address() string {
	return s.Server.Addr
}

// Stop stops s gracefully (or forcefully after timeout) and
// closes its listener.
func (s *Server) Stop() error {
	if s.closed {
		return errors.New("Server has been closed")
	}

	// Make sure a listener was set
	if s.listener != nil {
		// Close the listener to stop all new connections
		if err := s.listener.Close(); err != nil {
			return err
		}
	}

	s.Server.SetKeepAlivesEnabled(false)
	s.mu.Lock()
	s.closed = true
	s.mu.Unlock()

	// Wait for any connections to finish
	wait := make(chan struct{})
	go func() {
		defer close(wait)

		// Closing this signals any TLS governor goroutines to exit
		if s.tlsGovChan != nil {
			close(s.tlsGovChan)
		}

		s.connWg.Wait()
	}()

	// We block until all active connections are closed or the connTimeout happens
	select {
	case <-time.After(s.connTimeout):
		s.mu.Lock()
		for c, st := range s.conns {
			// Force close any idle and new connections.
			if st == http.StateIdle || st == http.StateNew {
				c.Close()
			}
		}
		s.mu.Unlock()
		return nil
	case <-wait:
		return nil
	}
}

// connState setups the ConnState tracking hook to know which connections are idle
func (s *Server) connState() {
	// Set our ConnState to track idle connections
	s.Server.ConnState = func(c net.Conn, cs http.ConnState) {
		s.mu.Lock()
		defer s.mu.Unlock()

		switch cs {
		case http.StateNew:
			// New connections increment the WaitGroup and are added the the conns dictionary
			s.connWg.Add(1)
			if s.conns == nil {
				s.conns = make(map[net.Conn]http.ConnState)
			}
			s.conns[c] = cs
		case http.StateActive:
			// Only update status to StateActive if it's in the conns dictionary
			if _, ok := s.conns[c]; ok {
				s.conns[c] = cs
			}
		case http.StateIdle:
			// Only update status to StateIdle if it's in the conns dictionary
			if _, ok := s.conns[c]; ok {
				s.conns[c] = cs
			}

			// If we've already closed then we need to close this connection.
			// We don't allow connections to become idle after server is closed
			if s.closed {
				c.Close()
			}
		case http.StateHijacked, http.StateClosed:
			// If the connection is hijacked or closed we forget it
			s.forgetConn(c)
		}
	}
}

// forgetConn removes c from conns and decrements WaitGroup
func (s *Server) forgetConn(c net.Conn) {
	if _, ok := s.conns[c]; ok {
		delete(s.conns, c)
		s.connWg.Done()
	}
}

// sanitizePath collapses any ./ ../ /// madness
// which helps prevent path traversal attacks.
// Note to middleware: use URL.RawPath If you need
// the "original" URL.Path value.
func sanitizePath(r *http.Request) {
	if r.URL.Path == "/" {
		return
	}
	cleanedPath := CleanPath(r.URL.Path)
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
		log.Println(output)
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

// MaxBytesExceeded is the error type returned by MaxBytesReader
// when the request body exceeds the limit imposed
type MaxBytesExceeded struct{}

func (err MaxBytesExceeded) Error() string {
	return "http: request body too large"
}

// MaxBytesReader and its associated methods are borrowed from the
// Go Standard library (comments intact). The only difference is that
// it returns a MaxBytesExceeded error instead of a generic error message
// when the request body has exceeded the requested limit
func MaxBytesReader(w http.ResponseWriter, r io.ReadCloser, n int64) io.ReadCloser {
	return &maxBytesReader{w: w, r: r, n: n}
}

type maxBytesReader struct {
	w   http.ResponseWriter
	r   io.ReadCloser // underlying reader
	n   int64         // max bytes remaining
	err error         // sticky error
}

func (l *maxBytesReader) Read(p []byte) (n int, err error) {
	if l.err != nil {
		return 0, l.err
	}
	if len(p) == 0 {
		return 0, nil
	}
	// If they asked for a 32KB byte read but only 5 bytes are
	// remaining, no need to read 32KB. 6 bytes will answer the
	// question of the whether we hit the limit or go past it.
	if int64(len(p)) > l.n+1 {
		p = p[:l.n+1]
	}
	n, err = l.r.Read(p)

	if int64(n) <= l.n {
		l.n -= int64(n)
		l.err = err
		return n, err
	}

	n = int(l.n)
	l.n = 0

	// The server code and client code both use
	// maxBytesReader. This "requestTooLarge" check is
	// only used by the server code. To prevent binaries
	// which only using the HTTP Client code (such as
	// cmd/go) from also linking in the HTTP server, don't
	// use a static type assertion to the server
	// "*response" type. Check this interface instead:
	type requestTooLarger interface {
		requestTooLarge()
	}
	if res, ok := l.w.(requestTooLarger); ok {
		res.requestTooLarge()
	}
	l.err = MaxBytesExceeded{}
	return n, l.err
}

func (l *maxBytesReader) Close() error {
	return l.r.Close()
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
