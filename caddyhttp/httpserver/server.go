// Package httpserver implements an HTTP server on top of Caddy.
package httpserver

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"log"
	"net"
	"net/http"
	"net/url"
	"os"
	"path"
	"path/filepath"
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
	connTimeout time.Duration // max time to wait for a connection before force stop
	tlsGovChan  chan struct{} // close to stop the TLS maintenance goroutine
	vhosts      *vhostTrie
}

// ensure it satisfies the interface
var _ caddy.GracefulServer = new(Server)

var defaultALPN = []string{"h2", "http/1.1"}

// makeTLSConfig extracts TLS settings from each site config to
// build a tls.Config usable in Caddy HTTP servers. The returned
// config will be nil if TLS is disabled for these sites.
func makeTLSConfig(group []*SiteConfig) (*tls.Config, error) {
	var tlsConfigs []*caddytls.Config
	for i := range group {
		if HTTP2 && len(group[i].TLS.ALPN) == 0 {
			// if no application-level protocol was configured up to now,
			// default to HTTP/2, then HTTP/1.1 if necessary
			group[i].TLS.ALPN = defaultALPN
		}
		tlsConfigs = append(tlsConfigs, group[i].TLS)
	}
	return caddytls.MakeTLSConfig(tlsConfigs)
}

// NewServer creates a new Server instance that will listen on addr
// and will serve the sites configured in group.
func NewServer(addr string, group []*SiteConfig) (*Server, error) {
	s := &Server{
		Server:      makeHTTPServerWithTimeouts(addr, group),
		vhosts:      newVHostTrie(),
		sites:       group,
		connTimeout: GracefulTimeout,
	}
	s.Server = makeHTTPServerWithHeaderLimit(s.Server, group)
	s.Server.Handler = s // this is weird, but whatever

	// extract TLS settings from each site config to build
	// a tls.Config, which will not be nil if TLS is enabled
	tlsConfig, err := makeTLSConfig(group)
	if err != nil {
		return nil, err
	}
	s.Server.TLSConfig = tlsConfig

	// Enable QUIC if desired
	if QUIC {
		s.quicServer = &h2quic.Server{Server: s.Server}
		s.Server.Handler = s.wrapWithSvcHeaders(s.Server.Handler)
	}

	// if TLS is enabled, make sure we prepare the Server accordingly
	if s.Server.TLSConfig != nil {
		// wrap the HTTP handler with a handler that does MITM detection
		tlsh := &tlsHandler{next: s.Server.Handler}
		s.Server.Handler = tlsh // this needs to be the "outer" handler when Serve() is called, for type assertion

		// when Serve() creates the TLS listener later, that listener should
		// be adding a reference the ClientHello info to a map; this callback
		// will be sure to clear out that entry when the connection closes.
		s.Server.ConnState = func(c net.Conn, cs http.ConnState) {
			// when a connection closes or is hijacked, delete its entry
			// in the map, because we are done with it.
			if tlsh.listener != nil {
				if cs == http.StateHijacked || cs == http.StateClosed {
					tlsh.listener.helloInfosMu.Lock()
					delete(tlsh.listener.helloInfos, c.RemoteAddr().String())
					tlsh.listener.helloInfosMu.Unlock()
				}
			}
		}

		// As of Go 1.7, if the Server's TLSConfig is not nil, HTTP/2 is enabled only
		// if TLSConfig.NextProtos includes the string "h2"
		if HTTP2 && len(s.Server.TLSConfig.NextProtos) == 0 {
			// some experimenting shows that this NextProtos must have at least
			// one value that overlaps with the NextProtos of any other tls.Config
			// that is returned from GetConfigForClient; if there is no overlap,
			// the connection will fail (as of Go 1.8, Feb. 2017).
			s.Server.TLSConfig.NextProtos = defaultALPN
		}
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

// makeHTTPServerWithHeaderLimit apply minimum header limit within a group to given http.Server
func makeHTTPServerWithHeaderLimit(s *http.Server, group []*SiteConfig) *http.Server {
	var min int64
	for _, cfg := range group {
		limit := cfg.Limits.MaxRequestHeaderSize
		if limit == 0 {
			continue
		}

		// not set yet
		if min == 0 {
			min = limit
		}

		// find a better one
		if limit < min {
			min = limit
		}
	}

	if min > 0 {
		s.MaxHeaderBytes = int(min)
	}
	return s
}

// makeHTTPServerWithTimeouts makes an http.Server from the group of
// configs in a way that configures timeouts (or, if not set, it uses
// the default timeouts) by combining the configuration of each
// SiteConfig in the group. (Timeouts are important for mitigating
// slowloris attacks.)
func makeHTTPServerWithTimeouts(addr string, group []*SiteConfig) *http.Server {
	// find the minimum duration configured for each timeout
	var min Timeouts
	for _, cfg := range group {
		if cfg.Timeouts.ReadTimeoutSet &&
			(!min.ReadTimeoutSet || cfg.Timeouts.ReadTimeout < min.ReadTimeout) {
			min.ReadTimeoutSet = true
			min.ReadTimeout = cfg.Timeouts.ReadTimeout
		}
		if cfg.Timeouts.ReadHeaderTimeoutSet &&
			(!min.ReadHeaderTimeoutSet || cfg.Timeouts.ReadHeaderTimeout < min.ReadHeaderTimeout) {
			min.ReadHeaderTimeoutSet = true
			min.ReadHeaderTimeout = cfg.Timeouts.ReadHeaderTimeout
		}
		if cfg.Timeouts.WriteTimeoutSet &&
			(!min.WriteTimeoutSet || cfg.Timeouts.WriteTimeout < min.WriteTimeout) {
			min.WriteTimeoutSet = true
			min.WriteTimeout = cfg.Timeouts.WriteTimeout
		}
		if cfg.Timeouts.IdleTimeoutSet &&
			(!min.IdleTimeoutSet || cfg.Timeouts.IdleTimeout < min.IdleTimeout) {
			min.IdleTimeoutSet = true
			min.IdleTimeout = cfg.Timeouts.IdleTimeout
		}
	}

	// for the values that were not set, use defaults
	if !min.ReadTimeoutSet {
		min.ReadTimeout = defaultTimeouts.ReadTimeout
	}
	if !min.ReadHeaderTimeoutSet {
		min.ReadHeaderTimeout = defaultTimeouts.ReadHeaderTimeout
	}
	if !min.WriteTimeoutSet {
		min.WriteTimeout = defaultTimeouts.WriteTimeout
	}
	if !min.IdleTimeoutSet {
		min.IdleTimeout = defaultTimeouts.IdleTimeout
	}

	// set the final values on the server and return it
	return &http.Server{
		Addr:              addr,
		ReadTimeout:       min.ReadTimeout,
		ReadHeaderTimeout: min.ReadHeaderTimeout,
		WriteTimeout:      min.WriteTimeout,
		IdleTimeout:       min.IdleTimeout,
	}
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

	if tcpLn, ok := ln.(*net.TCPListener); ok {
		ln = tcpKeepAliveListener{TCPListener: tcpLn}
	}

	cln := ln.(caddy.Listener)
	for _, site := range s.sites {
		for _, m := range site.listenerMiddleware {
			cln = m(cln)
		}
	}

	// Very important to return a concrete caddy.Listener
	// implementation for graceful restarts.
	return cln.(caddy.Listener), nil
}

// ListenPacket creates udp connection for QUIC if it is enabled,
func (s *Server) ListenPacket() (net.PacketConn, error) {
	if QUIC {
		udpAddr, err := net.ResolveUDPAddr("udp", s.Server.Addr)
		if err != nil {
			return nil, err
		}
		return net.ListenUDP("udp", udpAddr)
	}
	return nil, nil
}

// Serve serves requests on ln. It blocks until ln is closed.
func (s *Server) Serve(ln net.Listener) error {
	s.listenerMu.Lock()
	s.listener = ln
	s.listenerMu.Unlock()

	if s.Server.TLSConfig != nil {
		// Create TLS listener - note that we do not replace s.listener
		// with this TLS listener; tls.listener is unexported and does
		// not implement the File() method we need for graceful restarts
		// on POSIX systems.
		// TODO: Is this ^ still relevant anymore? Maybe we can now that it's a net.Listener...
		ln = newTLSListener(ln, s.Server.TLSConfig)
		if handler, ok := s.Server.Handler.(*tlsHandler); ok {
			handler.listener = ln.(*tlsHelloListener)
		}

		// Rotate TLS session ticket keys
		s.tlsGovChan = caddytls.RotateSessionTicketKeys(s.Server.TLSConfig)
	}

	err := s.Server.Serve(ln)
	if QUIC {
		s.quicServer.Close()
	}
	return err
}

// ServePacket serves QUIC requests on pc until it is closed.
func (s *Server) ServePacket(pc net.PacketConn) error {
	if QUIC {
		err := s.quicServer.Serve(pc.(*net.UDPConn))
		return fmt.Errorf("serving QUIC connections: %v", err)
	}
	return nil
}

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

	// copy the original, unchanged URL into the context
	// so it can be referenced by middlewares
	urlCopy := *r.URL
	if r.URL.User != nil {
		userInfo := new(url.Userinfo)
		*userInfo = *r.URL.User
		urlCopy.User = userInfo
	}
	c := context.WithValue(r.Context(), OriginalURLCtxKey, urlCopy)
	r = r.WithContext(c)

	w.Header().Set("Server", "Caddy")

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
	ctx, cancel := context.WithTimeout(context.Background(), s.connTimeout)
	defer cancel()

	err := s.Server.Shutdown(ctx)
	if err != nil {
		return err
	}

	// signal any TLS governor goroutines to exit
	if s.tlsGovChan != nil {
		close(s.tlsGovChan)
	}

	return nil
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

// defaultTimeouts stores the default timeout values to use
// if left unset by user configuration. NOTE: Default timeouts
// are disabled (see issue #1464).
var defaultTimeouts Timeouts

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

// ErrMaxBytesExceeded is the error returned by MaxBytesReader
// when the request body exceeds the limit imposed
var ErrMaxBytesExceeded = errors.New("http: request body too large")

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

// SafePath joins siteRoot and reqPath and converts it to a path that can
// be used to access a path on the local disk. It ensures the path does
// not traverse outside of the site root.
//
// If opening a file, use http.Dir instead.
func SafePath(siteRoot, reqPath string) string {
	reqPath = filepath.ToSlash(reqPath)
	reqPath = strings.Replace(reqPath, "\x00", "", -1) // NOTE: Go 1.9 checks for null bytes in the syscall package
	if siteRoot == "" {
		siteRoot = "."
	}
	return filepath.Join(siteRoot, filepath.FromSlash(path.Clean("/"+reqPath)))
}

// OriginalURLCtxKey is the key for accessing the original, incoming URL on an HTTP request.
const OriginalURLCtxKey = caddy.CtxKey("original_url")
