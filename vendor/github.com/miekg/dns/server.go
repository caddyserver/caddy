// DNS server implementation.

package dns

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/binary"
	"errors"
	"io"
	"net"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

// Default maximum number of TCP queries before we close the socket.
const maxTCPQueries = 128

// The maximum number of idle workers.
//
// This controls the maximum number of workers that are allowed to stay
// idle waiting for incoming requests before being torn down.
//
// If this limit is reached, the server will just keep spawning new
// workers (goroutines) for each incoming request. In this case, each
// worker will only be used for a single request.
const maxIdleWorkersCount = 10000

// The maximum length of time a worker may idle for before being destroyed.
const idleWorkerTimeout = 10 * time.Second

// aLongTimeAgo is a non-zero time, far in the past, used for
// immediate cancelation of network operations.
var aLongTimeAgo = time.Unix(1, 0)

// Handler is implemented by any value that implements ServeDNS.
type Handler interface {
	ServeDNS(w ResponseWriter, r *Msg)
}

// A ResponseWriter interface is used by an DNS handler to
// construct an DNS response.
type ResponseWriter interface {
	// LocalAddr returns the net.Addr of the server
	LocalAddr() net.Addr
	// RemoteAddr returns the net.Addr of the client that sent the current request.
	RemoteAddr() net.Addr
	// WriteMsg writes a reply back to the client.
	WriteMsg(*Msg) error
	// Write writes a raw buffer back to the client.
	Write([]byte) (int, error)
	// Close closes the connection.
	Close() error
	// TsigStatus returns the status of the Tsig.
	TsigStatus() error
	// TsigTimersOnly sets the tsig timers only boolean.
	TsigTimersOnly(bool)
	// Hijack lets the caller take over the connection.
	// After a call to Hijack(), the DNS package will not do anything with the connection.
	Hijack()
}

type response struct {
	msg            []byte
	hijacked       bool // connection has been hijacked by handler
	tsigStatus     error
	tsigTimersOnly bool
	tsigRequestMAC string
	tsigSecret     map[string]string // the tsig secrets
	udp            *net.UDPConn      // i/o connection if UDP was used
	tcp            net.Conn          // i/o connection if TCP was used
	udpSession     *SessionUDP       // oob data to get egress interface right
	writer         Writer            // writer to output the raw DNS bits
	wg             *sync.WaitGroup   // for gracefull shutdown
}

// ServeMux is an DNS request multiplexer. It matches the
// zone name of each incoming request against a list of
// registered patterns add calls the handler for the pattern
// that most closely matches the zone name. ServeMux is DNSSEC aware, meaning
// that queries for the DS record are redirected to the parent zone (if that
// is also registered), otherwise the child gets the query.
// ServeMux is also safe for concurrent access from multiple goroutines.
type ServeMux struct {
	z map[string]Handler
	m *sync.RWMutex
}

// NewServeMux allocates and returns a new ServeMux.
func NewServeMux() *ServeMux { return &ServeMux{z: make(map[string]Handler), m: new(sync.RWMutex)} }

// DefaultServeMux is the default ServeMux used by Serve.
var DefaultServeMux = NewServeMux()

// The HandlerFunc type is an adapter to allow the use of
// ordinary functions as DNS handlers.  If f is a function
// with the appropriate signature, HandlerFunc(f) is a
// Handler object that calls f.
type HandlerFunc func(ResponseWriter, *Msg)

// ServeDNS calls f(w, r).
func (f HandlerFunc) ServeDNS(w ResponseWriter, r *Msg) {
	f(w, r)
}

// HandleFailed returns a HandlerFunc that returns SERVFAIL for every request it gets.
func HandleFailed(w ResponseWriter, r *Msg) {
	m := new(Msg)
	m.SetRcode(r, RcodeServerFailure)
	// does not matter if this write fails
	w.WriteMsg(m)
}

func failedHandler() Handler { return HandlerFunc(HandleFailed) }

// ListenAndServe Starts a server on address and network specified Invoke handler
// for incoming queries.
func ListenAndServe(addr string, network string, handler Handler) error {
	server := &Server{Addr: addr, Net: network, Handler: handler}
	return server.ListenAndServe()
}

// ListenAndServeTLS acts like http.ListenAndServeTLS, more information in
// http://golang.org/pkg/net/http/#ListenAndServeTLS
func ListenAndServeTLS(addr, certFile, keyFile string, handler Handler) error {
	cert, err := tls.LoadX509KeyPair(certFile, keyFile)
	if err != nil {
		return err
	}

	config := tls.Config{
		Certificates: []tls.Certificate{cert},
	}

	server := &Server{
		Addr:      addr,
		Net:       "tcp-tls",
		TLSConfig: &config,
		Handler:   handler,
	}

	return server.ListenAndServe()
}

// ActivateAndServe activates a server with a listener from systemd,
// l and p should not both be non-nil.
// If both l and p are not nil only p will be used.
// Invoke handler for incoming queries.
func ActivateAndServe(l net.Listener, p net.PacketConn, handler Handler) error {
	server := &Server{Listener: l, PacketConn: p, Handler: handler}
	return server.ActivateAndServe()
}

func (mux *ServeMux) match(q string, t uint16) Handler {
	mux.m.RLock()
	defer mux.m.RUnlock()
	var handler Handler
	b := make([]byte, len(q)) // worst case, one label of length q
	off := 0
	end := false
	for {
		l := len(q[off:])
		for i := 0; i < l; i++ {
			b[i] = q[off+i]
			if b[i] >= 'A' && b[i] <= 'Z' {
				b[i] |= 'a' - 'A'
			}
		}
		if h, ok := mux.z[string(b[:l])]; ok { // causes garbage, might want to change the map key
			if t != TypeDS {
				return h
			}
			// Continue for DS to see if we have a parent too, if so delegeate to the parent
			handler = h
		}
		off, end = NextLabel(q, off)
		if end {
			break
		}
	}
	// Wildcard match, if we have found nothing try the root zone as a last resort.
	if h, ok := mux.z["."]; ok {
		return h
	}
	return handler
}

// Handle adds a handler to the ServeMux for pattern.
func (mux *ServeMux) Handle(pattern string, handler Handler) {
	if pattern == "" {
		panic("dns: invalid pattern " + pattern)
	}
	mux.m.Lock()
	mux.z[Fqdn(pattern)] = handler
	mux.m.Unlock()
}

// HandleFunc adds a handler function to the ServeMux for pattern.
func (mux *ServeMux) HandleFunc(pattern string, handler func(ResponseWriter, *Msg)) {
	mux.Handle(pattern, HandlerFunc(handler))
}

// HandleRemove deregistrars the handler specific for pattern from the ServeMux.
func (mux *ServeMux) HandleRemove(pattern string) {
	if pattern == "" {
		panic("dns: invalid pattern " + pattern)
	}
	mux.m.Lock()
	delete(mux.z, Fqdn(pattern))
	mux.m.Unlock()
}

// ServeDNS dispatches the request to the handler whose
// pattern most closely matches the request message. If DefaultServeMux
// is used the correct thing for DS queries is done: a possible parent
// is sought.
// If no handler is found a standard SERVFAIL message is returned
// If the request message does not have exactly one question in the
// question section a SERVFAIL is returned, unlesss Unsafe is true.
func (mux *ServeMux) ServeDNS(w ResponseWriter, request *Msg) {
	var h Handler
	if len(request.Question) < 1 { // allow more than one question
		h = failedHandler()
	} else {
		if h = mux.match(request.Question[0].Name, request.Question[0].Qtype); h == nil {
			h = failedHandler()
		}
	}
	h.ServeDNS(w, request)
}

// Handle registers the handler with the given pattern
// in the DefaultServeMux. The documentation for
// ServeMux explains how patterns are matched.
func Handle(pattern string, handler Handler) { DefaultServeMux.Handle(pattern, handler) }

// HandleRemove deregisters the handle with the given pattern
// in the DefaultServeMux.
func HandleRemove(pattern string) { DefaultServeMux.HandleRemove(pattern) }

// HandleFunc registers the handler function with the given pattern
// in the DefaultServeMux.
func HandleFunc(pattern string, handler func(ResponseWriter, *Msg)) {
	DefaultServeMux.HandleFunc(pattern, handler)
}

// Writer writes raw DNS messages; each call to Write should send an entire message.
type Writer interface {
	io.Writer
}

// Reader reads raw DNS messages; each call to ReadTCP or ReadUDP should return an entire message.
type Reader interface {
	// ReadTCP reads a raw message from a TCP connection. Implementations may alter
	// connection properties, for example the read-deadline.
	ReadTCP(conn net.Conn, timeout time.Duration) ([]byte, error)
	// ReadUDP reads a raw message from a UDP connection. Implementations may alter
	// connection properties, for example the read-deadline.
	ReadUDP(conn *net.UDPConn, timeout time.Duration) ([]byte, *SessionUDP, error)
}

// defaultReader is an adapter for the Server struct that implements the Reader interface
// using the readTCP and readUDP func of the embedded Server.
type defaultReader struct {
	*Server
}

func (dr *defaultReader) ReadTCP(conn net.Conn, timeout time.Duration) ([]byte, error) {
	return dr.readTCP(conn, timeout)
}

func (dr *defaultReader) ReadUDP(conn *net.UDPConn, timeout time.Duration) ([]byte, *SessionUDP, error) {
	return dr.readUDP(conn, timeout)
}

// DecorateReader is a decorator hook for extending or supplanting the functionality of a Reader.
// Implementations should never return a nil Reader.
type DecorateReader func(Reader) Reader

// DecorateWriter is a decorator hook for extending or supplanting the functionality of a Writer.
// Implementations should never return a nil Writer.
type DecorateWriter func(Writer) Writer

// A Server defines parameters for running an DNS server.
type Server struct {
	// Address to listen on, ":dns" if empty.
	Addr string
	// if "tcp" or "tcp-tls" (DNS over TLS) it will invoke a TCP listener, otherwise an UDP one
	Net string
	// TCP Listener to use, this is to aid in systemd's socket activation.
	Listener net.Listener
	// TLS connection configuration
	TLSConfig *tls.Config
	// UDP "Listener" to use, this is to aid in systemd's socket activation.
	PacketConn net.PacketConn
	// Handler to invoke, dns.DefaultServeMux if nil.
	Handler Handler
	// Default buffer size to use to read incoming UDP messages. If not set
	// it defaults to MinMsgSize (512 B).
	UDPSize int
	// The net.Conn.SetReadTimeout value for new connections, defaults to 2 * time.Second.
	ReadTimeout time.Duration
	// The net.Conn.SetWriteTimeout value for new connections, defaults to 2 * time.Second.
	WriteTimeout time.Duration
	// TCP idle timeout for multiple queries, if nil, defaults to 8 * time.Second (RFC 5966).
	IdleTimeout func() time.Duration
	// Secret(s) for Tsig map[<zonename>]<base64 secret>. The zonename must be in canonical form (lowercase, fqdn, see RFC 4034 Section 6.2).
	TsigSecret map[string]string
	// Unsafe instructs the server to disregard any sanity checks and directly hand the message to
	// the handler. It will specifically not check if the query has the QR bit not set.
	Unsafe bool
	// If NotifyStartedFunc is set it is called once the server has started listening.
	NotifyStartedFunc func()
	// DecorateReader is optional, allows customization of the process that reads raw DNS messages.
	DecorateReader DecorateReader
	// DecorateWriter is optional, allows customization of the process that writes raw DNS messages.
	DecorateWriter DecorateWriter
	// Maximum number of TCP queries before we close the socket. Default is maxTCPQueries (unlimited if -1).
	MaxTCPQueries int
	// Whether to set the SO_REUSEPORT socket option, allowing multiple listeners to be bound to a single address.
	// It is only supported on go1.11+ and when using ListenAndServe.
	ReusePort bool

	// UDP packet or TCP connection queue
	queue chan *response
	// Workers count
	workersCount int32

	// Shutdown handling
	lock     sync.RWMutex
	started  bool
	shutdown chan struct{}
	conns    map[net.Conn]struct{}

	// A pool for UDP message buffers.
	udpPool sync.Pool
}

func (srv *Server) isStarted() bool {
	srv.lock.RLock()
	started := srv.started
	srv.lock.RUnlock()
	return started
}

func (srv *Server) worker(w *response) {
	srv.serve(w)

	for {
		count := atomic.LoadInt32(&srv.workersCount)
		if count > maxIdleWorkersCount {
			return
		}
		if atomic.CompareAndSwapInt32(&srv.workersCount, count, count+1) {
			break
		}
	}

	defer atomic.AddInt32(&srv.workersCount, -1)

	inUse := false
	timeout := time.NewTimer(idleWorkerTimeout)
	defer timeout.Stop()
LOOP:
	for {
		select {
		case w, ok := <-srv.queue:
			if !ok {
				break LOOP
			}
			inUse = true
			srv.serve(w)
		case <-timeout.C:
			if !inUse {
				break LOOP
			}
			inUse = false
			timeout.Reset(idleWorkerTimeout)
		}
	}
}

func (srv *Server) spawnWorker(w *response) {
	select {
	case srv.queue <- w:
	default:
		go srv.worker(w)
	}
}

func makeUDPBuffer(size int) func() interface{} {
	return func() interface{} {
		return make([]byte, size)
	}
}

func (srv *Server) init() {
	srv.queue = make(chan *response)

	srv.shutdown = make(chan struct{})
	srv.conns = make(map[net.Conn]struct{})

	if srv.UDPSize == 0 {
		srv.UDPSize = MinMsgSize
	}

	srv.udpPool.New = makeUDPBuffer(srv.UDPSize)
}

func unlockOnce(l sync.Locker) func() {
	var once sync.Once
	return func() { once.Do(l.Unlock) }
}

// ListenAndServe starts a nameserver on the configured address in *Server.
func (srv *Server) ListenAndServe() error {
	unlock := unlockOnce(&srv.lock)
	srv.lock.Lock()
	defer unlock()

	if srv.started {
		return &Error{err: "server already started"}
	}

	addr := srv.Addr
	if addr == "" {
		addr = ":domain"
	}

	srv.init()
	defer close(srv.queue)

	switch srv.Net {
	case "tcp", "tcp4", "tcp6":
		l, err := listenTCP(srv.Net, addr, srv.ReusePort)
		if err != nil {
			return err
		}
		srv.Listener = l
		srv.started = true
		unlock()
		return srv.serveTCP(l)
	case "tcp-tls", "tcp4-tls", "tcp6-tls":
		if srv.TLSConfig == nil || (len(srv.TLSConfig.Certificates) == 0 && srv.TLSConfig.GetCertificate == nil) {
			return errors.New("dns: neither Certificates nor GetCertificate set in Config")
		}
		network := strings.TrimSuffix(srv.Net, "-tls")
		l, err := listenTCP(network, addr, srv.ReusePort)
		if err != nil {
			return err
		}
		l = tls.NewListener(l, srv.TLSConfig)
		srv.Listener = l
		srv.started = true
		unlock()
		return srv.serveTCP(l)
	case "udp", "udp4", "udp6":
		l, err := listenUDP(srv.Net, addr, srv.ReusePort)
		if err != nil {
			return err
		}
		u := l.(*net.UDPConn)
		if e := setUDPSocketOptions(u); e != nil {
			return e
		}
		srv.PacketConn = l
		srv.started = true
		unlock()
		return srv.serveUDP(u)
	}
	return &Error{err: "bad network"}
}

// ActivateAndServe starts a nameserver with the PacketConn or Listener
// configured in *Server. Its main use is to start a server from systemd.
func (srv *Server) ActivateAndServe() error {
	unlock := unlockOnce(&srv.lock)
	srv.lock.Lock()
	defer unlock()

	if srv.started {
		return &Error{err: "server already started"}
	}

	srv.init()
	defer close(srv.queue)

	pConn := srv.PacketConn
	l := srv.Listener
	if pConn != nil {
		// Check PacketConn interface's type is valid and value
		// is not nil
		if t, ok := pConn.(*net.UDPConn); ok && t != nil {
			if e := setUDPSocketOptions(t); e != nil {
				return e
			}
			srv.started = true
			unlock()
			return srv.serveUDP(t)
		}
	}
	if l != nil {
		srv.started = true
		unlock()
		return srv.serveTCP(l)
	}
	return &Error{err: "bad listeners"}
}

// Shutdown shuts down a server. After a call to Shutdown, ListenAndServe and
// ActivateAndServe will return.
func (srv *Server) Shutdown() error {
	return srv.ShutdownContext(context.Background())
}

// ShutdownContext shuts down a server. After a call to ShutdownContext,
// ListenAndServe and ActivateAndServe will return.
//
// A context.Context may be passed to limit how long to wait for connections
// to terminate.
func (srv *Server) ShutdownContext(ctx context.Context) error {
	srv.lock.Lock()
	started := srv.started
	srv.started = false
	srv.lock.Unlock()

	if !started {
		return &Error{err: "server not started"}
	}

	if srv.PacketConn != nil {
		srv.PacketConn.SetReadDeadline(aLongTimeAgo) // Unblock reads
	}

	if srv.Listener != nil {
		srv.Listener.Close()
	}

	srv.lock.Lock()
	for rw := range srv.conns {
		rw.SetReadDeadline(aLongTimeAgo) // Unblock reads
	}
	srv.lock.Unlock()

	if testShutdownNotify != nil {
		testShutdownNotify.Broadcast()
	}

	var ctxErr error
	select {
	case <-srv.shutdown:
	case <-ctx.Done():
		ctxErr = ctx.Err()
	}

	if srv.PacketConn != nil {
		srv.PacketConn.Close()
	}

	return ctxErr
}

var testShutdownNotify *sync.Cond

// getReadTimeout is a helper func to use system timeout if server did not intend to change it.
func (srv *Server) getReadTimeout() time.Duration {
	rtimeout := dnsTimeout
	if srv.ReadTimeout != 0 {
		rtimeout = srv.ReadTimeout
	}
	return rtimeout
}

// serveTCP starts a TCP listener for the server.
func (srv *Server) serveTCP(l net.Listener) error {
	defer l.Close()

	if srv.NotifyStartedFunc != nil {
		srv.NotifyStartedFunc()
	}

	var wg sync.WaitGroup
	defer func() {
		wg.Wait()
		close(srv.shutdown)
	}()

	for srv.isStarted() {
		rw, err := l.Accept()
		if err != nil {
			if !srv.isStarted() {
				return nil
			}
			if neterr, ok := err.(net.Error); ok && neterr.Temporary() {
				continue
			}
			return err
		}
		srv.lock.Lock()
		// Track the connection to allow unblocking reads on shutdown.
		srv.conns[rw] = struct{}{}
		srv.lock.Unlock()
		wg.Add(1)
		srv.spawnWorker(&response{
			tsigSecret: srv.TsigSecret,
			tcp:        rw,
			wg:         &wg,
		})
	}

	return nil
}

// serveUDP starts a UDP listener for the server.
func (srv *Server) serveUDP(l *net.UDPConn) error {
	defer l.Close()

	if srv.NotifyStartedFunc != nil {
		srv.NotifyStartedFunc()
	}

	reader := Reader(&defaultReader{srv})
	if srv.DecorateReader != nil {
		reader = srv.DecorateReader(reader)
	}

	var wg sync.WaitGroup
	defer func() {
		wg.Wait()
		close(srv.shutdown)
	}()

	rtimeout := srv.getReadTimeout()
	// deadline is not used here
	for srv.isStarted() {
		m, s, err := reader.ReadUDP(l, rtimeout)
		if err != nil {
			if !srv.isStarted() {
				return nil
			}
			if netErr, ok := err.(net.Error); ok && netErr.Temporary() {
				continue
			}
			return err
		}
		if len(m) < headerSize {
			if cap(m) == srv.UDPSize {
				srv.udpPool.Put(m[:srv.UDPSize])
			}
			continue
		}
		wg.Add(1)
		srv.spawnWorker(&response{
			msg:        m,
			tsigSecret: srv.TsigSecret,
			udp:        l,
			udpSession: s,
			wg:         &wg,
		})
	}

	return nil
}

func (srv *Server) serve(w *response) {
	if srv.DecorateWriter != nil {
		w.writer = srv.DecorateWriter(w)
	} else {
		w.writer = w
	}

	if w.udp != nil {
		// serve UDP
		srv.serveDNS(w)

		w.wg.Done()
		return
	}

	defer func() {
		if !w.hijacked {
			w.Close()
		}

		srv.lock.Lock()
		delete(srv.conns, w.tcp)
		srv.lock.Unlock()

		w.wg.Done()
	}()

	reader := Reader(&defaultReader{srv})
	if srv.DecorateReader != nil {
		reader = srv.DecorateReader(reader)
	}

	idleTimeout := tcpIdleTimeout
	if srv.IdleTimeout != nil {
		idleTimeout = srv.IdleTimeout()
	}

	timeout := srv.getReadTimeout()

	limit := srv.MaxTCPQueries
	if limit == 0 {
		limit = maxTCPQueries
	}

	for q := 0; (q < limit || limit == -1) && srv.isStarted(); q++ {
		var err error
		w.msg, err = reader.ReadTCP(w.tcp, timeout)
		if err != nil {
			// TODO(tmthrgd): handle error
			break
		}
		srv.serveDNS(w)
		if w.tcp == nil {
			break // Close() was called
		}
		if w.hijacked {
			break // client will call Close() themselves
		}
		// The first read uses the read timeout, the rest use the
		// idle timeout.
		timeout = idleTimeout
	}
}

func (srv *Server) serveDNS(w *response) {
	req := new(Msg)
	err := req.Unpack(w.msg)
	if w.udp != nil && cap(w.msg) == srv.UDPSize {
		srv.udpPool.Put(w.msg[:srv.UDPSize])
	}
	w.msg = nil
	if err != nil { // Send a FormatError back
		x := new(Msg)
		x.SetRcodeFormatError(req)
		w.WriteMsg(x)
		return
	}
	if !srv.Unsafe && req.Response {
		return
	}

	w.tsigStatus = nil
	if w.tsigSecret != nil {
		if t := req.IsTsig(); t != nil {
			if secret, ok := w.tsigSecret[t.Hdr.Name]; ok {
				w.tsigStatus = TsigVerify(w.msg, secret, "", false)
			} else {
				w.tsigStatus = ErrSecret
			}
			w.tsigTimersOnly = false
			w.tsigRequestMAC = req.Extra[len(req.Extra)-1].(*TSIG).MAC
		}
	}

	handler := srv.Handler
	if handler == nil {
		handler = DefaultServeMux
	}

	handler.ServeDNS(w, req) // Writes back to the client
}

func (srv *Server) readTCP(conn net.Conn, timeout time.Duration) ([]byte, error) {
	conn.SetReadDeadline(time.Now().Add(timeout))
	l := make([]byte, 2)
	n, err := conn.Read(l)
	if err != nil || n != 2 {
		if err != nil {
			return nil, err
		}
		return nil, ErrShortRead
	}
	length := binary.BigEndian.Uint16(l)
	if length == 0 {
		return nil, ErrShortRead
	}
	m := make([]byte, int(length))
	n, err = conn.Read(m[:int(length)])
	if err != nil || n == 0 {
		if err != nil {
			return nil, err
		}
		return nil, ErrShortRead
	}
	i := n
	for i < int(length) {
		j, err := conn.Read(m[i:int(length)])
		if err != nil {
			return nil, err
		}
		i += j
	}
	n = i
	m = m[:n]
	return m, nil
}

func (srv *Server) readUDP(conn *net.UDPConn, timeout time.Duration) ([]byte, *SessionUDP, error) {
	conn.SetReadDeadline(time.Now().Add(timeout))
	m := srv.udpPool.Get().([]byte)
	n, s, err := ReadFromSessionUDP(conn, m)
	if err != nil {
		srv.udpPool.Put(m)
		return nil, nil, err
	}
	m = m[:n]
	return m, s, nil
}

// WriteMsg implements the ResponseWriter.WriteMsg method.
func (w *response) WriteMsg(m *Msg) (err error) {
	var data []byte
	if w.tsigSecret != nil { // if no secrets, dont check for the tsig (which is a longer check)
		if t := m.IsTsig(); t != nil {
			data, w.tsigRequestMAC, err = TsigGenerate(m, w.tsigSecret[t.Hdr.Name], w.tsigRequestMAC, w.tsigTimersOnly)
			if err != nil {
				return err
			}
			_, err = w.writer.Write(data)
			return err
		}
	}
	data, err = m.Pack()
	if err != nil {
		return err
	}
	_, err = w.writer.Write(data)
	return err
}

// Write implements the ResponseWriter.Write method.
func (w *response) Write(m []byte) (int, error) {
	switch {
	case w.udp != nil:
		n, err := WriteToSessionUDP(w.udp, m, w.udpSession)
		return n, err
	case w.tcp != nil:
		lm := len(m)
		if lm < 2 {
			return 0, io.ErrShortBuffer
		}
		if lm > MaxMsgSize {
			return 0, &Error{err: "message too large"}
		}
		l := make([]byte, 2, 2+lm)
		binary.BigEndian.PutUint16(l, uint16(lm))
		m = append(l, m...)

		n, err := io.Copy(w.tcp, bytes.NewReader(m))
		return int(n), err
	}
	panic("not reached")
}

// LocalAddr implements the ResponseWriter.LocalAddr method.
func (w *response) LocalAddr() net.Addr {
	if w.tcp != nil {
		return w.tcp.LocalAddr()
	}
	return w.udp.LocalAddr()
}

// RemoteAddr implements the ResponseWriter.RemoteAddr method.
func (w *response) RemoteAddr() net.Addr {
	if w.tcp != nil {
		return w.tcp.RemoteAddr()
	}
	return w.udpSession.RemoteAddr()
}

// TsigStatus implements the ResponseWriter.TsigStatus method.
func (w *response) TsigStatus() error { return w.tsigStatus }

// TsigTimersOnly implements the ResponseWriter.TsigTimersOnly method.
func (w *response) TsigTimersOnly(b bool) { w.tsigTimersOnly = b }

// Hijack implements the ResponseWriter.Hijack method.
func (w *response) Hijack() { w.hijacked = true }

// Close implements the ResponseWriter.Close method
func (w *response) Close() error {
	// Can't close the udp conn, as that is actually the listener.
	if w.tcp != nil {
		e := w.tcp.Close()
		w.tcp = nil
		return e
	}
	return nil
}
