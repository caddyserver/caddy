package h2quic

import (
	"crypto/tls"
	"errors"
	"fmt"
	"net"
	"net/http"
	"runtime"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	quic "github.com/lucas-clemente/quic-go"
	"github.com/lucas-clemente/quic-go/internal/protocol"
	"github.com/lucas-clemente/quic-go/internal/utils"
	"github.com/lucas-clemente/quic-go/qerr"
	"golang.org/x/net/http2"
	"golang.org/x/net/http2/hpack"
)

type streamCreator interface {
	quic.Session
	GetOrOpenStream(protocol.StreamID) (quic.Stream, error)
}

type remoteCloser interface {
	CloseRemote(protocol.ByteCount)
}

// allows mocking of quic.Listen and quic.ListenAddr
var (
	quicListen     = quic.Listen
	quicListenAddr = quic.ListenAddr
)

// Server is a HTTP2 server listening for QUIC connections.
type Server struct {
	*http.Server

	// By providing a quic.Config, it is possible to set parameters of the QUIC connection.
	// If nil, it uses reasonable default values.
	QuicConfig *quic.Config

	// Private flag for demo, do not use
	CloseAfterFirstRequest bool

	port uint32 // used atomically

	listenerMutex sync.Mutex
	listener      quic.Listener
	closed        bool

	supportedVersionsAsString string
}

// ListenAndServe listens on the UDP address s.Addr and calls s.Handler to handle HTTP/2 requests on incoming connections.
func (s *Server) ListenAndServe() error {
	if s.Server == nil {
		return errors.New("use of h2quic.Server without http.Server")
	}
	return s.serveImpl(s.TLSConfig, nil)
}

// ListenAndServeTLS listens on the UDP address s.Addr and calls s.Handler to handle HTTP/2 requests on incoming connections.
func (s *Server) ListenAndServeTLS(certFile, keyFile string) error {
	var err error
	certs := make([]tls.Certificate, 1)
	certs[0], err = tls.LoadX509KeyPair(certFile, keyFile)
	if err != nil {
		return err
	}
	// We currently only use the cert-related stuff from tls.Config,
	// so we don't need to make a full copy.
	config := &tls.Config{
		Certificates: certs,
	}
	return s.serveImpl(config, nil)
}

// Serve an existing UDP connection.
func (s *Server) Serve(conn net.PacketConn) error {
	return s.serveImpl(s.TLSConfig, conn)
}

func (s *Server) serveImpl(tlsConfig *tls.Config, conn net.PacketConn) error {
	if s.Server == nil {
		return errors.New("use of h2quic.Server without http.Server")
	}
	s.listenerMutex.Lock()
	if s.closed {
		s.listenerMutex.Unlock()
		return errors.New("Server is already closed")
	}
	if s.listener != nil {
		s.listenerMutex.Unlock()
		return errors.New("ListenAndServe may only be called once")
	}

	var ln quic.Listener
	var err error
	if conn == nil {
		ln, err = quicListenAddr(s.Addr, tlsConfig, s.QuicConfig)
	} else {
		ln, err = quicListen(conn, tlsConfig, s.QuicConfig)
	}
	if err != nil {
		s.listenerMutex.Unlock()
		return err
	}
	s.listener = ln
	s.listenerMutex.Unlock()

	for {
		sess, err := ln.Accept()
		if err != nil {
			return err
		}
		go s.handleHeaderStream(sess.(streamCreator))
	}
}

func (s *Server) handleHeaderStream(session streamCreator) {
	stream, err := session.AcceptStream()
	if err != nil {
		session.Close(qerr.Error(qerr.InvalidHeadersStreamData, err.Error()))
		return
	}

	hpackDecoder := hpack.NewDecoder(4096, nil)
	h2framer := http2.NewFramer(nil, stream)

	var headerStreamMutex sync.Mutex // Protects concurrent calls to Write()
	for {
		if err := s.handleRequest(session, stream, &headerStreamMutex, hpackDecoder, h2framer); err != nil {
			// QuicErrors must originate from stream.Read() returning an error.
			// In this case, the session has already logged the error, so we don't
			// need to log it again.
			if _, ok := err.(*qerr.QuicError); !ok {
				utils.Errorf("error handling h2 request: %s", err.Error())
			}
			session.Close(err)
			return
		}
	}
}

func (s *Server) handleRequest(session streamCreator, headerStream quic.Stream, headerStreamMutex *sync.Mutex, hpackDecoder *hpack.Decoder, h2framer *http2.Framer) error {
	h2frame, err := h2framer.ReadFrame()
	if err != nil {
		return qerr.Error(qerr.HeadersStreamDataDecompressFailure, "cannot read frame")
	}
	h2headersFrame, ok := h2frame.(*http2.HeadersFrame)
	if !ok {
		return qerr.Error(qerr.InvalidHeadersStreamData, "expected a header frame")
	}
	if !h2headersFrame.HeadersEnded() {
		return errors.New("http2 header continuation not implemented")
	}
	headers, err := hpackDecoder.DecodeFull(h2headersFrame.HeaderBlockFragment())
	if err != nil {
		utils.Errorf("invalid http2 headers encoding: %s", err.Error())
		return err
	}

	req, err := requestFromHeaders(headers)
	if err != nil {
		return err
	}

	if utils.Debug() {
		utils.Infof("%s %s%s, on data stream %d", req.Method, req.Host, req.RequestURI, h2headersFrame.StreamID)
	} else {
		utils.Infof("%s %s%s", req.Method, req.Host, req.RequestURI)
	}

	dataStream, err := session.GetOrOpenStream(protocol.StreamID(h2headersFrame.StreamID))
	if err != nil {
		return err
	}
	// this can happen if the client immediately closes the data stream after sending the request and the runtime processes the reset before the request
	if dataStream == nil {
		return nil
	}

	// handleRequest should be as non-blocking as possible to minimize
	// head-of-line blocking. Potentially blocking code is run in a separate
	// goroutine, enabling handleRequest to return before the code is executed.
	go func() {
		streamEnded := h2headersFrame.StreamEnded()
		if streamEnded {
			dataStream.(remoteCloser).CloseRemote(0)
			streamEnded = true
			_, _ = dataStream.Read([]byte{0}) // read the eof
		}

		req = req.WithContext(dataStream.Context())
		reqBody := newRequestBody(dataStream)
		req.Body = reqBody

		req.RemoteAddr = session.RemoteAddr().String()

		responseWriter := newResponseWriter(headerStream, headerStreamMutex, dataStream, protocol.StreamID(h2headersFrame.StreamID))

		handler := s.Handler
		if handler == nil {
			handler = http.DefaultServeMux
		}
		panicked := false
		func() {
			defer func() {
				if p := recover(); p != nil {
					// Copied from net/http/server.go
					const size = 64 << 10
					buf := make([]byte, size)
					buf = buf[:runtime.Stack(buf, false)]
					utils.Errorf("http: panic serving: %v\n%s", p, buf)
					panicked = true
				}
			}()
			handler.ServeHTTP(responseWriter, req)
		}()
		if panicked {
			responseWriter.WriteHeader(500)
		} else {
			responseWriter.WriteHeader(200)
		}
		if responseWriter.dataStream != nil {
			if !streamEnded && !reqBody.requestRead {
				// in gQUIC, the error code doesn't matter, so just use 0 here
				responseWriter.dataStream.CancelRead(0)
			}
			responseWriter.dataStream.Close()
		}
		if s.CloseAfterFirstRequest {
			time.Sleep(100 * time.Millisecond)
			session.Close(nil)
		}
	}()

	return nil
}

// Close the server immediately, aborting requests and sending CONNECTION_CLOSE frames to connected clients.
// Close in combination with ListenAndServe() (instead of Serve()) may race if it is called before a UDP socket is established.
func (s *Server) Close() error {
	s.listenerMutex.Lock()
	defer s.listenerMutex.Unlock()
	s.closed = true
	if s.listener != nil {
		err := s.listener.Close()
		s.listener = nil
		return err
	}
	return nil
}

// CloseGracefully shuts down the server gracefully. The server sends a GOAWAY frame first, then waits for either timeout to trigger, or for all running requests to complete.
// CloseGracefully in combination with ListenAndServe() (instead of Serve()) may race if it is called before a UDP socket is established.
func (s *Server) CloseGracefully(timeout time.Duration) error {
	// TODO: implement
	return nil
}

// SetQuicHeaders can be used to set the proper headers that announce that this server supports QUIC.
// The values that are set depend on the port information from s.Server.Addr, and currently look like this (if Addr has port 443):
//  Alt-Svc: quic=":443"; ma=2592000; v="33,32,31,30"
func (s *Server) SetQuicHeaders(hdr http.Header) error {
	port := atomic.LoadUint32(&s.port)

	if port == 0 {
		// Extract port from s.Server.Addr
		_, portStr, err := net.SplitHostPort(s.Server.Addr)
		if err != nil {
			return err
		}
		portInt, err := net.LookupPort("tcp", portStr)
		if err != nil {
			return err
		}
		port = uint32(portInt)
		atomic.StoreUint32(&s.port, port)
	}

	if s.supportedVersionsAsString == "" {
		var versions []string
		for _, v := range protocol.SupportedVersions {
			versions = append(versions, v.ToAltSvc())
		}
		s.supportedVersionsAsString = strings.Join(versions, ",")
	}

	hdr.Add("Alt-Svc", fmt.Sprintf(`quic=":%d"; ma=2592000; v="%s"`, port, s.supportedVersionsAsString))

	return nil
}

// ListenAndServeQUIC listens on the UDP network address addr and calls the
// handler for HTTP/2 requests on incoming connections. http.DefaultServeMux is
// used when handler is nil.
func ListenAndServeQUIC(addr, certFile, keyFile string, handler http.Handler) error {
	server := &Server{
		Server: &http.Server{
			Addr:    addr,
			Handler: handler,
		},
	}
	return server.ListenAndServeTLS(certFile, keyFile)
}

// ListenAndServe listens on the given network address for both, TLS and QUIC
// connetions in parallel. It returns if one of the two returns an error.
// http.DefaultServeMux is used when handler is nil.
// The correct Alt-Svc headers for QUIC are set.
func ListenAndServe(addr, certFile, keyFile string, handler http.Handler) error {
	// Load certs
	var err error
	certs := make([]tls.Certificate, 1)
	certs[0], err = tls.LoadX509KeyPair(certFile, keyFile)
	if err != nil {
		return err
	}
	// We currently only use the cert-related stuff from tls.Config,
	// so we don't need to make a full copy.
	config := &tls.Config{
		Certificates: certs,
	}

	// Open the listeners
	udpAddr, err := net.ResolveUDPAddr("udp", addr)
	if err != nil {
		return err
	}
	udpConn, err := net.ListenUDP("udp", udpAddr)
	if err != nil {
		return err
	}
	defer udpConn.Close()

	tcpAddr, err := net.ResolveTCPAddr("tcp", addr)
	if err != nil {
		return err
	}
	tcpConn, err := net.ListenTCP("tcp", tcpAddr)
	if err != nil {
		return err
	}
	defer tcpConn.Close()

	tlsConn := tls.NewListener(tcpConn, config)
	defer tlsConn.Close()

	// Start the servers
	httpServer := &http.Server{
		Addr:      addr,
		TLSConfig: config,
	}

	quicServer := &Server{
		Server: httpServer,
	}

	if handler == nil {
		handler = http.DefaultServeMux
	}
	httpServer.Handler = http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		quicServer.SetQuicHeaders(w.Header())
		handler.ServeHTTP(w, r)
	})

	hErr := make(chan error)
	qErr := make(chan error)
	go func() {
		hErr <- httpServer.Serve(tlsConn)
	}()
	go func() {
		qErr <- quicServer.Serve(udpConn)
	}()

	select {
	case err := <-hErr:
		quicServer.Close()
		return err
	case err := <-qErr:
		// Cannot close the HTTP server or wait for requests to complete properly :/
		return err
	}
}
