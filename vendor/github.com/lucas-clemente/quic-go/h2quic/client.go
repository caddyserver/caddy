package h2quic

import (
	"crypto/tls"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"strings"
	"sync"

	"golang.org/x/net/http2"
	"golang.org/x/net/http2/hpack"
	"golang.org/x/net/idna"

	quic "github.com/lucas-clemente/quic-go"
	"github.com/lucas-clemente/quic-go/internal/utils"
	"github.com/lucas-clemente/quic-go/protocol"
	"github.com/lucas-clemente/quic-go/qerr"
)

type roundTripperOpts struct {
	DisableCompression bool
}

var dialAddr = quic.DialAddr

// client is a HTTP2 client doing QUIC requests
type client struct {
	mutex sync.RWMutex

	tlsConf *tls.Config
	config  *quic.Config
	opts    *roundTripperOpts

	hostname        string
	encryptionLevel protocol.EncryptionLevel
	handshakeErr    error
	dialOnce        sync.Once

	session       quic.Session
	headerStream  quic.Stream
	headerErr     *qerr.QuicError
	headerErrored chan struct{} // this channel is closed if an error occurs on the header stream
	requestWriter *requestWriter

	responses map[protocol.StreamID]chan *http.Response
}

var _ http.RoundTripper = &client{}

var defaultQuicConfig = &quic.Config{
	RequestConnectionIDTruncation: true,
	KeepAlive:                     true,
}

// newClient creates a new client
func newClient(
	hostname string,
	tlsConfig *tls.Config,
	opts *roundTripperOpts,
	quicConfig *quic.Config,
) *client {
	config := defaultQuicConfig
	if quicConfig != nil {
		config = quicConfig
	}
	return &client{
		hostname:        authorityAddr("https", hostname),
		responses:       make(map[protocol.StreamID]chan *http.Response),
		encryptionLevel: protocol.EncryptionUnencrypted,
		tlsConf:         tlsConfig,
		config:          config,
		opts:            opts,
		headerErrored:   make(chan struct{}),
	}
}

// dial dials the connection
func (c *client) dial() error {
	var err error
	c.session, err = dialAddr(c.hostname, c.tlsConf, c.config)
	if err != nil {
		return err
	}

	// once the version has been negotiated, open the header stream
	c.headerStream, err = c.session.OpenStream()
	if err != nil {
		return err
	}
	if c.headerStream.StreamID() != 3 {
		return errors.New("h2quic Client BUG: StreamID of Header Stream is not 3")
	}
	c.requestWriter = newRequestWriter(c.headerStream)
	go c.handleHeaderStream()
	return nil
}

func (c *client) handleHeaderStream() {
	decoder := hpack.NewDecoder(4096, func(hf hpack.HeaderField) {})
	h2framer := http2.NewFramer(nil, c.headerStream)

	var lastStream protocol.StreamID

	for {
		frame, err := h2framer.ReadFrame()
		if err != nil {
			c.headerErr = qerr.Error(qerr.HeadersStreamDataDecompressFailure, "cannot read frame")
			break
		}
		lastStream = protocol.StreamID(frame.Header().StreamID)
		hframe, ok := frame.(*http2.HeadersFrame)
		if !ok {
			c.headerErr = qerr.Error(qerr.InvalidHeadersStreamData, "not a headers frame")
			break
		}
		mhframe := &http2.MetaHeadersFrame{HeadersFrame: hframe}
		mhframe.Fields, err = decoder.DecodeFull(hframe.HeaderBlockFragment())
		if err != nil {
			c.headerErr = qerr.Error(qerr.InvalidHeadersStreamData, "cannot read header fields")
			break
		}

		c.mutex.RLock()
		responseChan, ok := c.responses[protocol.StreamID(hframe.StreamID)]
		c.mutex.RUnlock()
		if !ok {
			c.headerErr = qerr.Error(qerr.InternalError, fmt.Sprintf("h2client BUG: response channel for stream %d not found", lastStream))
			break
		}

		rsp, err := responseFromHeaders(mhframe)
		if err != nil {
			c.headerErr = qerr.Error(qerr.InternalError, err.Error())
		}
		responseChan <- rsp
	}

	// stop all running request
	utils.Debugf("Error handling header stream %d: %s", lastStream, c.headerErr.Error())
	close(c.headerErrored)
}

// Roundtrip executes a request and returns a response
func (c *client) RoundTrip(req *http.Request) (*http.Response, error) {
	// TODO: add port to address, if it doesn't have one
	if req.URL.Scheme != "https" {
		return nil, errors.New("quic http2: unsupported scheme")
	}
	if authorityAddr("https", hostnameFromRequest(req)) != c.hostname {
		return nil, fmt.Errorf("h2quic Client BUG: RoundTrip called for the wrong client (expected %s, got %s)", c.hostname, req.Host)
	}

	c.dialOnce.Do(func() {
		c.handshakeErr = c.dial()
	})

	if c.handshakeErr != nil {
		return nil, c.handshakeErr
	}

	hasBody := (req.Body != nil)

	responseChan := make(chan *http.Response)
	dataStream, err := c.session.OpenStreamSync()
	if err != nil {
		_ = c.CloseWithError(err)
		return nil, err
	}
	c.mutex.Lock()
	c.responses[dataStream.StreamID()] = responseChan
	c.mutex.Unlock()

	var requestedGzip bool
	if !c.opts.DisableCompression && req.Header.Get("Accept-Encoding") == "" && req.Header.Get("Range") == "" && req.Method != "HEAD" {
		requestedGzip = true
	}
	// TODO: add support for trailers
	endStream := !hasBody
	err = c.requestWriter.WriteRequest(req, dataStream.StreamID(), endStream, requestedGzip)
	if err != nil {
		_ = c.CloseWithError(err)
		return nil, err
	}

	resc := make(chan error, 1)
	if hasBody {
		go func() {
			resc <- c.writeRequestBody(dataStream, req.Body)
		}()
	}

	var res *http.Response

	var receivedResponse bool
	var bodySent bool

	if !hasBody {
		bodySent = true
	}

	for !(bodySent && receivedResponse) {
		select {
		case res = <-responseChan:
			receivedResponse = true
			c.mutex.Lock()
			delete(c.responses, dataStream.StreamID())
			c.mutex.Unlock()
		case err := <-resc:
			bodySent = true
			if err != nil {
				return nil, err
			}
		case <-c.headerErrored:
			// an error occured on the header stream
			_ = c.CloseWithError(c.headerErr)
			return nil, c.headerErr
		}
	}

	// TODO: correctly set this variable
	var streamEnded bool
	isHead := (req.Method == "HEAD")

	res = setLength(res, isHead, streamEnded)

	if streamEnded || isHead {
		res.Body = noBody
	} else {
		res.Body = dataStream
		if requestedGzip && res.Header.Get("Content-Encoding") == "gzip" {
			res.Header.Del("Content-Encoding")
			res.Header.Del("Content-Length")
			res.ContentLength = -1
			res.Body = &gzipReader{body: res.Body}
			res.Uncompressed = true
		}
	}

	res.Request = req
	return res, nil
}

func (c *client) writeRequestBody(dataStream quic.Stream, body io.ReadCloser) (err error) {
	defer func() {
		cerr := body.Close()
		if err == nil {
			// TODO: what to do with dataStream here? Maybe reset it?
			err = cerr
		}
	}()

	_, err = io.Copy(dataStream, body)
	if err != nil {
		// TODO: what to do with dataStream here? Maybe reset it?
		return err
	}
	return dataStream.Close()
}

// Close closes the client
func (c *client) CloseWithError(e error) error {
	if c.session == nil {
		return nil
	}
	return c.session.Close(e)
}

func (c *client) Close() error {
	return c.CloseWithError(nil)
}

// copied from net/transport.go

// authorityAddr returns a given authority (a host/IP, or host:port / ip:port)
// and returns a host:port. The port 443 is added if needed.
func authorityAddr(scheme string, authority string) (addr string) {
	host, port, err := net.SplitHostPort(authority)
	if err != nil { // authority didn't have a port
		port = "443"
		if scheme == "http" {
			port = "80"
		}
		host = authority
	}
	if a, err := idna.ToASCII(host); err == nil {
		host = a
	}
	// IPv6 address literal, without a port:
	if strings.HasPrefix(host, "[") && strings.HasSuffix(host, "]") {
		return host + ":" + port
	}
	return net.JoinHostPort(host, port)
}
