package syslog

import (
	"bufio"
	"crypto/tls"
	"errors"
	"net"
	"strings"
	"sync"
	"time"

	"gopkg.in/mcuadros/go-syslog.v2/format"
)

var (
	RFC3164   = &format.RFC3164{}   // RFC3164: http://www.ietf.org/rfc/rfc3164.txt
	RFC5424   = &format.RFC5424{}   // RFC5424: http://www.ietf.org/rfc/rfc5424.txt
	RFC6587   = &format.RFC6587{}   // RFC6587: http://www.ietf.org/rfc/rfc6587.txt - octet counting variant
	Automatic = &format.Automatic{} // Automatically identify the format
)

const (
	datagramChannelBufferSize = 10
	datagramReadBufferSize    = 64 * 1024
)

// A function type which gets the TLS peer name from the connection. Can return
// ok=false to terminate the connection
type TlsPeerNameFunc func(tlsConn *tls.Conn) (tlsPeer string, ok bool)

type Server struct {
	listeners               []net.Listener
	connections             []net.PacketConn
	wait                    sync.WaitGroup
	doneTcp                 chan bool
	datagramChannel         chan DatagramMessage
	format                  format.Format
	handler                 Handler
	lastError               error
	readTimeoutMilliseconds int64
	tlsPeerNameFunc         TlsPeerNameFunc
	datagramPool            sync.Pool
}

//NewServer returns a new Server
func NewServer() *Server {
	return &Server{tlsPeerNameFunc: defaultTlsPeerName, datagramPool: sync.Pool{
		New: func() interface{} {
			return make([]byte, 65536)
		},
	}}
}

//Sets the syslog format (RFC3164 or RFC5424 or RFC6587)
func (s *Server) SetFormat(f format.Format) {
	s.format = f
}

//Sets the handler, this handler with receive every syslog entry
func (s *Server) SetHandler(handler Handler) {
	s.handler = handler
}

//Sets the connection timeout for TCP connections, in milliseconds
func (s *Server) SetTimeout(millseconds int64) {
	s.readTimeoutMilliseconds = millseconds
}

// Set the function that extracts a TLS peer name from the TLS connection
func (s *Server) SetTlsPeerNameFunc(tlsPeerNameFunc TlsPeerNameFunc) {
	s.tlsPeerNameFunc = tlsPeerNameFunc
}

// Default TLS peer name function - returns the CN of the certificate
func defaultTlsPeerName(tlsConn *tls.Conn) (tlsPeer string, ok bool) {
	state := tlsConn.ConnectionState()
	if len(state.PeerCertificates) <= 0 {
		return "", false
	}
	cn := state.PeerCertificates[0].Subject.CommonName
	return cn, true
}

//Configure the server for listen on an UDP addr
func (s *Server) ListenUDP(addr string) error {
	udpAddr, err := net.ResolveUDPAddr("udp", addr)
	if err != nil {
		return err
	}

	connection, err := net.ListenUDP("udp", udpAddr)
	if err != nil {
		return err
	}
	connection.SetReadBuffer(datagramReadBufferSize)

	s.connections = append(s.connections, connection)
	return nil
}

//Configure the server for listen on an unix socket
func (s *Server) ListenUnixgram(addr string) error {
	unixAddr, err := net.ResolveUnixAddr("unixgram", addr)
	if err != nil {
		return err
	}

	connection, err := net.ListenUnixgram("unixgram", unixAddr)
	if err != nil {
		return err
	}
	connection.SetReadBuffer(datagramReadBufferSize)

	s.connections = append(s.connections, connection)
	return nil
}

//Configure the server for listen on a TCP addr
func (s *Server) ListenTCP(addr string) error {
	tcpAddr, err := net.ResolveTCPAddr("tcp", addr)
	if err != nil {
		return err
	}

	listener, err := net.ListenTCP("tcp", tcpAddr)
	if err != nil {
		return err
	}

	s.doneTcp = make(chan bool)
	s.listeners = append(s.listeners, listener)
	return nil
}

//Configure the server for listen on a TCP addr for TLS
func (s *Server) ListenTCPTLS(addr string, config *tls.Config) error {
	listener, err := tls.Listen("tcp", addr, config)
	if err != nil {
		return err
	}

	s.doneTcp = make(chan bool)
	s.listeners = append(s.listeners, listener)
	return nil
}

//Starts the server, all the go routines goes to live
func (s *Server) Boot() error {
	if s.format == nil {
		return errors.New("please set a valid format")
	}

	if s.handler == nil {
		return errors.New("please set a valid handler")
	}

	for _, listener := range s.listeners {
		s.goAcceptConnection(listener)
	}

	if len(s.connections) > 0 {
		s.goParseDatagrams()
	}

	for _, connection := range s.connections {
		s.goReceiveDatagrams(connection)
	}

	return nil
}

func (s *Server) goAcceptConnection(listener net.Listener) {
	s.wait.Add(1)
	go func(listener net.Listener) {
	loop:
		for {
			select {
			case <-s.doneTcp:
				break loop
			default:
			}
			connection, err := listener.Accept()
			if err != nil {
				continue
			}

			s.goScanConnection(connection)
		}

		s.wait.Done()
	}(listener)
}

func (s *Server) goScanConnection(connection net.Conn) {
	scanner := bufio.NewScanner(connection)
	if sf := s.format.GetSplitFunc(); sf != nil {
		scanner.Split(sf)
	}

	remoteAddr := connection.RemoteAddr()
	var client string
	if remoteAddr != nil {
		client = remoteAddr.String()
	}

	tlsPeer := ""
	if tlsConn, ok := connection.(*tls.Conn); ok {
		// Handshake now so we get the TLS peer information
		if err := tlsConn.Handshake(); err != nil {
			connection.Close()
			return
		}
		if s.tlsPeerNameFunc != nil {
			var ok bool
			tlsPeer, ok = s.tlsPeerNameFunc(tlsConn)
			if !ok {
				connection.Close()
				return
			}
		}
	}

	var scanCloser *ScanCloser
	scanCloser = &ScanCloser{scanner, connection}

	s.wait.Add(1)
	go s.scan(scanCloser, client, tlsPeer)
}

func (s *Server) scan(scanCloser *ScanCloser, client string, tlsPeer string) {
loop:
	for {
		select {
		case <-s.doneTcp:
			break loop
		default:
		}
		if s.readTimeoutMilliseconds > 0 {
			scanCloser.closer.SetReadDeadline(time.Now().Add(time.Duration(s.readTimeoutMilliseconds) * time.Millisecond))
		}
		if scanCloser.Scan() {
			s.parser([]byte(scanCloser.Text()), client, tlsPeer)
		} else {
			break loop
		}
	}
	scanCloser.closer.Close()

	s.wait.Done()
}

func (s *Server) parser(line []byte, client string, tlsPeer string) {
	parser := s.format.GetParser(line)
	err := parser.Parse()
	if err != nil {
		s.lastError = err
	}

	logParts := parser.Dump()
	logParts["client"] = client
	if logParts["hostname"] == "" && s.format == RFC3164 {
		if i := strings.Index(client, ":"); i > 1 {
			logParts["hostname"] = client[:i]
		} else {
			logParts["hostname"] = client
		}
	}
	logParts["tls_peer"] = tlsPeer

	s.handler.Handle(logParts, int64(len(line)), err)
}

//Returns the last error
func (s *Server) GetLastError() error {
	return s.lastError
}

//Kill the server
func (s *Server) Kill() error {
	for _, connection := range s.connections {
		err := connection.Close()
		if err != nil {
			return err
		}
	}

	for _, listener := range s.listeners {
		err := listener.Close()
		if err != nil {
			return err
		}
	}
	// Only need to close channel once to broadcast to all waiting
	if s.doneTcp != nil {
		close(s.doneTcp)
	}
	if s.datagramChannel != nil {
		close(s.datagramChannel)
	}
	return nil
}

//Waits until the server stops
func (s *Server) Wait() {
	s.wait.Wait()
}

type TimeoutCloser interface {
	Close() error
	SetReadDeadline(t time.Time) error
}

type ScanCloser struct {
	*bufio.Scanner
	closer TimeoutCloser
}

type DatagramMessage struct {
	message []byte
	client  string
}

func (s *Server) goReceiveDatagrams(packetconn net.PacketConn) {
	s.wait.Add(1)
	go func() {
		defer s.wait.Done()
		for {
			buf := s.datagramPool.Get().([]byte)
			n, addr, err := packetconn.ReadFrom(buf)
			if err == nil {
				// Ignore trailing control characters and NULs
				for ; (n > 0) && (buf[n-1] < 32); n-- {
				}
				if n > 0 {
					var address string
					if addr != nil {
						address = addr.String()
					}
					s.datagramChannel <- DatagramMessage{buf[:n], address}
				}
			} else {
				// there has been an error. Either the server has been killed
				// or may be getting a transitory error due to (e.g.) the
				// interface being shutdown in which case sleep() to avoid busy wait.
				opError, ok := err.(*net.OpError)
				if (ok) && !opError.Temporary() && !opError.Timeout() {
					return
				}
				time.Sleep(10 * time.Millisecond)
			}
		}
	}()
}

func (s *Server) goParseDatagrams() {
	s.datagramChannel = make(chan DatagramMessage, datagramChannelBufferSize)

	s.wait.Add(1)
	go func() {
		defer s.wait.Done()
		for {
			select {
			case msg, ok := (<-s.datagramChannel):
				if !ok {
					return
				}
				if sf := s.format.GetSplitFunc(); sf != nil {
					if _, token, err := sf(msg.message, true); err == nil {
						s.parser(token, msg.client, "")
					}
				} else {
					s.parser(msg.message, msg.client, "")
				}
				s.datagramPool.Put(msg.message[:cap(msg.message)])
			}
		}
	}()
}
