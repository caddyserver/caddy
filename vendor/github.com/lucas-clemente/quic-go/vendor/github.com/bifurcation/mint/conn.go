package mint

import (
	"crypto"
	"crypto/x509"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"net"
	"reflect"
	"sync"
	"time"
)

type Certificate struct {
	Chain      []*x509.Certificate
	PrivateKey crypto.Signer
}

type PreSharedKey struct {
	CipherSuite  CipherSuite
	IsResumption bool
	Identity     []byte
	Key          []byte
	NextProto    string
	ReceivedAt   time.Time
	ExpiresAt    time.Time
	TicketAgeAdd uint32
}

type PreSharedKeyCache interface {
	Get(string) (PreSharedKey, bool)
	Put(string, PreSharedKey)
	Size() int
}

// A CookieHandler can be used to give the application more fine-grained control over Cookies.
// Generate receives the Conn as an argument, so the CookieHandler can decide when to send the cookie based on that, and offload state to the client by encoding that into the Cookie.
// When the client echoes the Cookie, Validate is called. The application can then recover the state from the cookie.
type CookieHandler interface {
	// Generate a byte string that is sent as a part of a cookie to the client in the HelloRetryRequest
	// If Generate returns nil, mint will not send a HelloRetryRequest.
	Generate(*Conn) ([]byte, error)
	// Validate is called when receiving a ClientHello containing a Cookie.
	// If validation failed, the handshake is aborted.
	Validate(*Conn, []byte) bool
}

type PSKMapCache map[string]PreSharedKey

func (cache PSKMapCache) Get(key string) (psk PreSharedKey, ok bool) {
	psk, ok = cache[key]
	return
}

func (cache *PSKMapCache) Put(key string, psk PreSharedKey) {
	(*cache)[key] = psk
}

func (cache PSKMapCache) Size() int {
	return len(cache)
}

// Config is the struct used to pass configuration settings to a TLS client or
// server instance.  The settings for client and server are pretty different,
// but we just throw them all in here.
type Config struct {
	// Client fields
	ServerName string

	// Server fields
	SendSessionTickets bool
	TicketLifetime     uint32
	TicketLen          int
	EarlyDataLifetime  uint32
	AllowEarlyData     bool
	// Require the client to echo a cookie.
	RequireCookie bool
	// A CookieHandler can be used to set and validate a cookie.
	// The cookie returned by the CookieHandler will be part of the cookie sent on the wire, and encoded using the CookieProtector.
	// If no CookieHandler is set, mint will always send a cookie.
	// The CookieHandler can be used to decide on a per-connection basis, if a cookie should be sent.
	CookieHandler CookieHandler
	// The CookieProtector is used to encrypt / decrypt cookies.
	// It should make sure that the Cookie cannot be read and tampered with by the client.
	// If non-blocking mode is used, and cookies are required, this field has to be set.
	// In blocking mode, a default cookie protector is used, if this is unused.
	CookieProtector CookieProtector
	// The ExtensionHandler is used to add custom extensions.
	ExtensionHandler  AppExtensionHandler
	RequireClientAuth bool

	// Time returns the current time as the number of seconds since the epoch.
	// If Time is nil, TLS uses time.Now.
	Time func() time.Time
	// RootCAs defines the set of root certificate authorities
	// that clients use when verifying server certificates.
	// If RootCAs is nil, TLS uses the host's root CA set.
	RootCAs *x509.CertPool
	// InsecureSkipVerify controls whether a client verifies the
	// server's certificate chain and host name.
	// If InsecureSkipVerify is true, TLS accepts any certificate
	// presented by the server and any host name in that certificate.
	// In this mode, TLS is susceptible to man-in-the-middle attacks.
	// This should be used only for testing.
	InsecureSkipVerify bool

	// Shared fields
	Certificates []*Certificate
	// VerifyPeerCertificate, if not nil, is called after normal
	// certificate verification by either a TLS client or server. It
	// receives the raw ASN.1 certificates provided by the peer and also
	// any verified chains that normal processing found. If it returns a
	// non-nil error, the handshake is aborted and that error results.
	//
	// If normal verification fails then the handshake will abort before
	// considering this callback. If normal verification is disabled by
	// setting InsecureSkipVerify then this callback will be considered but
	// the verifiedChains argument will always be nil.
	VerifyPeerCertificate func(rawCerts [][]byte, verifiedChains [][]*x509.Certificate) error

	CipherSuites     []CipherSuite
	Groups           []NamedGroup
	SignatureSchemes []SignatureScheme
	NextProtos       []string
	PSKs             PreSharedKeyCache
	PSKModes         []PSKKeyExchangeMode
	NonBlocking      bool
	UseDTLS          bool

	// The same config object can be shared among different connections, so it
	// needs its own mutex
	mutex sync.RWMutex
}

// Clone returns a shallow clone of c. It is safe to clone a Config that is
// being used concurrently by a TLS client or server.
func (c *Config) Clone() *Config {
	c.mutex.Lock()
	defer c.mutex.Unlock()

	return &Config{
		ServerName: c.ServerName,

		SendSessionTickets: c.SendSessionTickets,
		TicketLifetime:     c.TicketLifetime,
		TicketLen:          c.TicketLen,
		EarlyDataLifetime:  c.EarlyDataLifetime,
		AllowEarlyData:     c.AllowEarlyData,
		RequireCookie:      c.RequireCookie,
		CookieHandler:      c.CookieHandler,
		CookieProtector:    c.CookieProtector,
		ExtensionHandler:   c.ExtensionHandler,
		RequireClientAuth:  c.RequireClientAuth,
		Time:               c.Time,
		RootCAs:            c.RootCAs,
		InsecureSkipVerify: c.InsecureSkipVerify,

		Certificates:          c.Certificates,
		VerifyPeerCertificate: c.VerifyPeerCertificate,
		CipherSuites:          c.CipherSuites,
		Groups:                c.Groups,
		SignatureSchemes:      c.SignatureSchemes,
		NextProtos:            c.NextProtos,
		PSKs:                  c.PSKs,
		PSKModes:              c.PSKModes,
		NonBlocking:           c.NonBlocking,
		UseDTLS:               c.UseDTLS,
	}
}

func (c *Config) Init(isClient bool) error {
	c.mutex.Lock()
	defer c.mutex.Unlock()

	// Set defaults
	if len(c.CipherSuites) == 0 {
		c.CipherSuites = defaultSupportedCipherSuites
	}
	if len(c.Groups) == 0 {
		c.Groups = defaultSupportedGroups
	}
	if len(c.SignatureSchemes) == 0 {
		c.SignatureSchemes = defaultSignatureSchemes
	}
	if c.TicketLen == 0 {
		c.TicketLen = defaultTicketLen
	}
	if !reflect.ValueOf(c.PSKs).IsValid() {
		c.PSKs = &PSKMapCache{}
	}
	if len(c.PSKModes) == 0 {
		c.PSKModes = defaultPSKModes
	}
	return nil
}

func (c *Config) ValidForServer() bool {
	return (reflect.ValueOf(c.PSKs).IsValid() && c.PSKs.Size() > 0) ||
		(len(c.Certificates) > 0 &&
			len(c.Certificates[0].Chain) > 0 &&
			c.Certificates[0].PrivateKey != nil)
}

func (c *Config) ValidForClient() bool {
	return len(c.ServerName) > 0
}

func (c *Config) time() time.Time {
	t := c.Time
	if t == nil {
		t = time.Now
	}
	return t()
}

var (
	defaultSupportedCipherSuites = []CipherSuite{
		TLS_AES_128_GCM_SHA256,
		TLS_AES_256_GCM_SHA384,
	}

	defaultSupportedGroups = []NamedGroup{
		P256,
		P384,
		FFDHE2048,
		X25519,
	}

	defaultSignatureSchemes = []SignatureScheme{
		RSA_PSS_SHA256,
		RSA_PSS_SHA384,
		RSA_PSS_SHA512,
		ECDSA_P256_SHA256,
		ECDSA_P384_SHA384,
		ECDSA_P521_SHA512,
	}

	defaultTicketLen = 16

	defaultPSKModes = []PSKKeyExchangeMode{
		PSKModeKE,
		PSKModeDHEKE,
	}
)

type ConnectionState struct {
	HandshakeState   State
	CipherSuite      CipherSuiteParams     // cipher suite in use (TLS_RSA_WITH_RC4_128_SHA, ...)
	PeerCertificates []*x509.Certificate   // certificate chain presented by remote peer
	VerifiedChains   [][]*x509.Certificate // verified chains built from PeerCertificates
	NextProto        string                // Selected ALPN proto
	UsingPSK         bool                  // Are we using PSK.
	UsingEarlyData   bool                  // Did we negotiate 0-RTT.
}

// Conn implements the net.Conn interface, as with "crypto/tls"
// * Read, Write, and Close are provided locally
// * LocalAddr, RemoteAddr, and Set*Deadline are forwarded to the inner Conn
type Conn struct {
	config   *Config
	conn     net.Conn
	isClient bool

	state             stateConnected
	hState            HandshakeState
	handshakeMutex    sync.Mutex
	handshakeAlert    Alert
	handshakeComplete bool

	readBuffer []byte
	in, out    *RecordLayer
	hsCtx      *HandshakeContext
}

func NewConn(conn net.Conn, config *Config, isClient bool) *Conn {
	c := &Conn{conn: conn, config: config, isClient: isClient, hsCtx: &HandshakeContext{}}
	if !config.UseDTLS {
		c.in = NewRecordLayerTLS(c.conn, directionRead)
		c.out = NewRecordLayerTLS(c.conn, directionWrite)
		c.hsCtx.hIn = NewHandshakeLayerTLS(c.hsCtx, c.in)
		c.hsCtx.hOut = NewHandshakeLayerTLS(c.hsCtx, c.out)
	} else {
		c.in = NewRecordLayerDTLS(c.conn, directionRead)
		c.out = NewRecordLayerDTLS(c.conn, directionWrite)
		c.hsCtx.hIn = NewHandshakeLayerDTLS(c.hsCtx, c.in)
		c.hsCtx.hOut = NewHandshakeLayerDTLS(c.hsCtx, c.out)
		c.hsCtx.timeoutMS = initialTimeout
		c.hsCtx.timers = newTimerSet()
		c.hsCtx.waitingNextFlight = true
	}
	c.in.label = c.label()
	c.out.label = c.label()
	c.hsCtx.hIn.nonblocking = c.config.NonBlocking
	return c
}

// Read up
func (c *Conn) consumeRecord() error {
	pt, err := c.in.ReadRecord()
	if pt == nil {
		logf(logTypeIO, "extendBuffer returns error %v", err)
		return err
	}

	switch pt.contentType {
	case RecordTypeHandshake:
		logf(logTypeHandshake, "Received post-handshake message")
		// We do not support fragmentation of post-handshake handshake messages.
		// TODO: Factor this more elegantly; coalesce with handshakeLayer.ReadMessage()
		start := 0
		headerLen := handshakeHeaderLenTLS
		if c.config.UseDTLS {
			headerLen = handshakeHeaderLenDTLS
		}
		for start < len(pt.fragment) {
			if len(pt.fragment[start:]) < headerLen {
				return fmt.Errorf("Post-handshake handshake message too short for header")
			}

			hm := &HandshakeMessage{}
			hm.msgType = HandshakeType(pt.fragment[start])
			hmLen := (int(pt.fragment[start+1]) << 16) + (int(pt.fragment[start+2]) << 8) + int(pt.fragment[start+3])

			if len(pt.fragment[start+headerLen:]) < hmLen {
				return fmt.Errorf("Post-handshake handshake message too short for body")
			}
			hm.body = pt.fragment[start+headerLen : start+headerLen+hmLen]

			// XXX: If we want to support more advanced cases, e.g., post-handshake
			// authentication, we'll need to allow transitions other than
			// Connected -> Connected
			state, actions, alert := c.state.ProcessMessage(hm)
			if alert != AlertNoAlert {
				logf(logTypeHandshake, "Error in state transition: %v", alert)
				c.sendAlert(alert)
				return io.EOF
			}

			for _, action := range actions {
				alert = c.takeAction(action)
				if alert != AlertNoAlert {
					logf(logTypeHandshake, "Error during handshake actions: %v", alert)
					c.sendAlert(alert)
					return io.EOF
				}
			}

			var connected bool
			c.state, connected = state.(stateConnected)
			if !connected {
				logf(logTypeHandshake, "Disconnected after state transition: %v", alert)
				c.sendAlert(alert)
				return io.EOF
			}

			start += headerLen + hmLen
		}
	case RecordTypeAlert:
		logf(logTypeIO, "extended buffer (for alert): [%d] %x", len(c.readBuffer), c.readBuffer)
		if len(pt.fragment) != 2 {
			c.sendAlert(AlertUnexpectedMessage)
			return io.EOF
		}
		if Alert(pt.fragment[1]) == AlertCloseNotify {
			return io.EOF
		}

		switch pt.fragment[0] {
		case AlertLevelWarning:
			// drop on the floor
		case AlertLevelError:
			return Alert(pt.fragment[1])
		default:
			c.sendAlert(AlertUnexpectedMessage)
			return io.EOF
		}

	case RecordTypeAck:
		if !c.hsCtx.hIn.datagram {
			logf(logTypeHandshake, "Received ACK in TLS mode")
			return AlertUnexpectedMessage
		}
		return c.hsCtx.processAck(pt.fragment)

	case RecordTypeApplicationData:
		c.readBuffer = append(c.readBuffer, pt.fragment...)
		logf(logTypeIO, "extended buffer: [%d] %x", len(c.readBuffer), c.readBuffer)

	}

	return err
}

func readPartial(in *[]byte, buffer []byte) int {
	logf(logTypeIO, "conn.Read input buffer now has len %d", len((*in)))
	read := copy(buffer, *in)
	*in = (*in)[read:]

	logf(logTypeVerbose, "Returning %v", string(buffer))
	return read
}

// Read application data up to the size of buffer.  Handshake and alert records
// are consumed by the Conn object directly.
func (c *Conn) Read(buffer []byte) (int, error) {
	if _, connected := c.hState.(stateConnected); !connected {
		// Clients can't call Read prior to handshake completion.
		if c.isClient {
			return 0, errors.New("Read called before the handshake completed")
		}

		// Neither can servers that don't allow early data.
		if !c.config.AllowEarlyData {
			return 0, errors.New("Read called before the handshake completed")
		}

		// If there's no early data, then return WouldBlock
		if len(c.hsCtx.earlyData) == 0 {
			return 0, AlertWouldBlock
		}

		return readPartial(&c.hsCtx.earlyData, buffer), nil
	}

	// The handshake is now connected.
	logf(logTypeHandshake, "conn.Read with buffer = %d", len(buffer))
	if alert := c.Handshake(); alert != AlertNoAlert {
		return 0, alert
	}

	if len(buffer) == 0 {
		return 0, nil
	}

	// Run our timers.
	if c.config.UseDTLS {
		if err := c.hsCtx.timers.check(time.Now()); err != nil {
			return 0, AlertInternalError
		}
	}

	// Lock the input channel
	c.in.Lock()
	defer c.in.Unlock()
	for len(c.readBuffer) == 0 {
		err := c.consumeRecord()

		// err can be nil if consumeRecord processed a non app-data
		// record.
		if err != nil {
			if c.config.NonBlocking || err != AlertWouldBlock {
				logf(logTypeIO, "conn.Read returns err=%v", err)
				return 0, err
			}
		}
	}

	return readPartial(&c.readBuffer, buffer), nil
}

// Write application data
func (c *Conn) Write(buffer []byte) (int, error) {
	// Lock the output channel
	c.out.Lock()
	defer c.out.Unlock()

	if !c.Writable() {
		return 0, errors.New("Write called before the handshake completed (and early data not in use)")
	}

	// Send full-size fragments
	var start int
	sent := 0
	for start = 0; len(buffer)-start >= maxFragmentLen; start += maxFragmentLen {
		err := c.out.WriteRecord(&TLSPlaintext{
			contentType: RecordTypeApplicationData,
			fragment:    buffer[start : start+maxFragmentLen],
		})

		if err != nil {
			return sent, err
		}
		sent += maxFragmentLen
	}

	// Send a final partial fragment if necessary
	if start < len(buffer) {
		err := c.out.WriteRecord(&TLSPlaintext{
			contentType: RecordTypeApplicationData,
			fragment:    buffer[start:],
		})

		if err != nil {
			return sent, err
		}
		sent += len(buffer[start:])
	}
	return sent, nil
}

// sendAlert sends a TLS alert message.
// c.out.Mutex <= L.
func (c *Conn) sendAlert(err Alert) error {
	c.handshakeMutex.Lock()
	defer c.handshakeMutex.Unlock()

	var level int
	switch err {
	case AlertNoRenegotiation, AlertCloseNotify:
		level = AlertLevelWarning
	default:
		level = AlertLevelError
	}

	buf := []byte{byte(err), byte(level)}
	c.out.WriteRecord(&TLSPlaintext{
		contentType: RecordTypeAlert,
		fragment:    buf,
	})

	// close_notify and end_of_early_data are not actually errors
	if level == AlertLevelWarning {
		return &net.OpError{Op: "local error", Err: err}
	}

	return c.Close()
}

// Close closes the connection.
func (c *Conn) Close() error {
	// XXX crypto/tls has an interlock with Write here.  Do we need that?

	return c.conn.Close()
}

// LocalAddr returns the local network address.
func (c *Conn) LocalAddr() net.Addr {
	return c.conn.LocalAddr()
}

// RemoteAddr returns the remote network address.
func (c *Conn) RemoteAddr() net.Addr {
	return c.conn.RemoteAddr()
}

// SetDeadline sets the read and write deadlines associated with the connection.
// A zero value for t means Read and Write will not time out.
// After a Write has timed out, the TLS state is corrupt and all future writes will return the same error.
func (c *Conn) SetDeadline(t time.Time) error {
	return c.conn.SetDeadline(t)
}

// SetReadDeadline sets the read deadline on the underlying connection.
// A zero value for t means Read will not time out.
func (c *Conn) SetReadDeadline(t time.Time) error {
	return c.conn.SetReadDeadline(t)
}

// SetWriteDeadline sets the write deadline on the underlying connection.
// A zero value for t means Write will not time out.
// After a Write has timed out, the TLS state is corrupt and all future writes will return the same error.
func (c *Conn) SetWriteDeadline(t time.Time) error {
	return c.conn.SetWriteDeadline(t)
}

func (c *Conn) takeAction(actionGeneric HandshakeAction) Alert {
	label := "[server]"
	if c.isClient {
		label = "[client]"
	}

	switch action := actionGeneric.(type) {
	case QueueHandshakeMessage:
		logf(logTypeHandshake, "%s queuing handshake message type=%v", label, action.Message.msgType)
		err := c.hsCtx.hOut.QueueMessage(action.Message)
		if err != nil {
			logf(logTypeHandshake, "%s Error writing handshake message: %v", label, err)
			return AlertInternalError
		}

	case SendQueuedHandshake:
		_, err := c.hsCtx.hOut.SendQueuedMessages()
		if err != nil {
			logf(logTypeHandshake, "%s Error writing handshake message: %v", label, err)
			return AlertInternalError
		}
		if c.config.UseDTLS {
			c.hsCtx.timers.start(retransmitTimerLabel,
				c.hsCtx.handshakeRetransmit,
				c.hsCtx.timeoutMS)
		}
	case RekeyIn:
		logf(logTypeHandshake, "%s Rekeying in to %s: %+v", label, action.epoch.label(), action.KeySet)
		// Check that we don't have an input data in the handshake frame parser.
		if len(c.hsCtx.hIn.frame.remainder) > 0 {
			logf(logTypeHandshake, "%s Rekey with data still in handshake buffers", label)
			return AlertDecodeError
		}
		err := c.in.Rekey(action.epoch, action.KeySet.cipher, action.KeySet.key, action.KeySet.iv)
		if err != nil {
			logf(logTypeHandshake, "%s Unable to rekey inbound: %v", label, err)
			return AlertInternalError
		}

	case RekeyOut:
		logf(logTypeHandshake, "%s Rekeying out to %s: %+v", label, action.epoch.label(), action.KeySet)
		err := c.out.Rekey(action.epoch, action.KeySet.cipher, action.KeySet.key, action.KeySet.iv)
		if err != nil {
			logf(logTypeHandshake, "%s Unable to rekey outbound: %v", label, err)
			return AlertInternalError
		}

	case ResetOut:
		logf(logTypeHandshake, "%s Rekeying out to %s seq=%v", label, EpochClear, action.seq)
		c.out.ResetClear(action.seq)

	case StorePSK:
		logf(logTypeHandshake, "%s Storing new session ticket with identity [%x]", label, action.PSK.Identity)
		if c.isClient {
			// Clients look up PSKs based on server name
			c.config.PSKs.Put(c.config.ServerName, action.PSK)
		} else {
			// Servers look them up based on the identity in the extension
			c.config.PSKs.Put(hex.EncodeToString(action.PSK.Identity), action.PSK)
		}

	default:
		logf(logTypeHandshake, "%s Unknown action type", label)
		assert(false)
		return AlertInternalError
	}

	return AlertNoAlert
}

func (c *Conn) HandshakeSetup() Alert {
	var state HandshakeState
	var actions []HandshakeAction
	var alert Alert

	if err := c.config.Init(c.isClient); err != nil {
		logf(logTypeHandshake, "Error initializing config: %v", err)
		return AlertInternalError
	}

	opts := ConnectionOptions{
		ServerName: c.config.ServerName,
		NextProtos: c.config.NextProtos,
	}

	if c.isClient {
		state, actions, alert = clientStateStart{Config: c.config, Opts: opts, hsCtx: c.hsCtx}.Next(nil)
		if alert != AlertNoAlert {
			logf(logTypeHandshake, "Error initializing client state: %v", alert)
			return alert
		}

		for _, action := range actions {
			alert = c.takeAction(action)
			if alert != AlertNoAlert {
				logf(logTypeHandshake, "Error during handshake actions: %v", alert)
				return alert
			}
		}
	} else {
		if c.config.RequireCookie && c.config.CookieProtector == nil {
			logf(logTypeHandshake, "RequireCookie set, but no CookieProtector provided. Using default cookie protector. Stateless Retry not possible.")
			if c.config.NonBlocking {
				logf(logTypeHandshake, "Not possible in non-blocking mode.")
				return AlertInternalError
			}
			var err error
			c.config.CookieProtector, err = NewDefaultCookieProtector()
			if err != nil {
				logf(logTypeHandshake, "Error initializing cookie source: %v", alert)
				return AlertInternalError
			}
		}
		state = serverStateStart{Config: c.config, conn: c, hsCtx: c.hsCtx}
	}

	c.hState = state
	return AlertNoAlert
}

type handshakeMessageReader interface {
	ReadMessage() (*HandshakeMessage, Alert)
}

type handshakeMessageReaderImpl struct {
	hsCtx *HandshakeContext
}

var _ handshakeMessageReader = &handshakeMessageReaderImpl{}

func (r *handshakeMessageReaderImpl) ReadMessage() (*HandshakeMessage, Alert) {
	var hm *HandshakeMessage
	var err error
	for {
		hm, err = r.hsCtx.hIn.ReadMessage()
		if err == AlertWouldBlock {
			return nil, AlertWouldBlock
		}
		if err != nil {
			logf(logTypeHandshake, "Error reading message: %v", err)
			return nil, AlertCloseNotify
		}
		if hm != nil {
			break
		}
	}

	return hm, AlertNoAlert
}

// Handshake causes a TLS handshake on the connection.  The `isClient` member
// determines whether a client or server handshake is performed.  If a
// handshake has already been performed, then its result will be returned.
func (c *Conn) Handshake() Alert {
	label := "[server]"
	if c.isClient {
		label = "[client]"
	}

	// TODO Lock handshakeMutex
	// TODO Remove CloseNotify hack
	if c.handshakeAlert != AlertNoAlert && c.handshakeAlert != AlertCloseNotify {
		logf(logTypeHandshake, "Pre-existing handshake error: %v", c.handshakeAlert)
		return c.handshakeAlert
	}
	if c.handshakeComplete {
		return AlertNoAlert
	}

	if c.hState == nil {
		logf(logTypeHandshake, "%s First time through handshake (or after stateless retry), setting up", label)
		alert := c.HandshakeSetup()
		if alert != AlertNoAlert || (c.isClient && c.config.NonBlocking) {
			return alert
		}
	}

	logf(logTypeHandshake, "(Re-)entering handshake, state=%v", c.hState)
	state := c.hState
	_, connected := state.(stateConnected)

	hmr := &handshakeMessageReaderImpl{hsCtx: c.hsCtx}
	for !connected {
		var alert Alert
		var actions []HandshakeAction

		// Advance the state machine
		state, actions, alert = state.Next(hmr)
		if alert == AlertWouldBlock {
			logf(logTypeHandshake, "%s Would block reading message: %s", label, alert)
			// If we blocked, then run our timers to see if any have expired.
			if c.hsCtx.hIn.datagram {
				if err := c.hsCtx.timers.check(time.Now()); err != nil {
					return AlertInternalError
				}
			}
			return AlertWouldBlock
		}
		if alert == AlertCloseNotify {
			logf(logTypeHandshake, "%s Error reading message: %s", label, alert)
			c.sendAlert(AlertCloseNotify)
			return AlertCloseNotify
		}
		if alert != AlertNoAlert && alert != AlertStatelessRetry {
			logf(logTypeHandshake, "Error in state transition: %v", alert)
			return alert
		}

		for index, action := range actions {
			logf(logTypeHandshake, "%s taking next action (%d)", label, index)
			if alert := c.takeAction(action); alert != AlertNoAlert {
				logf(logTypeHandshake, "Error during handshake actions: %v", alert)
				c.sendAlert(alert)
				return alert
			}
		}

		c.hState = state
		logf(logTypeHandshake, "state is now %s", c.GetHsState())
		_, connected = state.(stateConnected)
		if connected {
			c.state = state.(stateConnected)
			c.handshakeComplete = true

			if !c.isClient {
				// Send NewSessionTicket if configured to
				if c.config.SendSessionTickets {
					actions, alert := c.state.NewSessionTicket(
						c.config.TicketLen,
						c.config.TicketLifetime,
						c.config.EarlyDataLifetime)

					for _, action := range actions {
						alert = c.takeAction(action)
						if alert != AlertNoAlert {
							logf(logTypeHandshake, "Error during handshake actions: %v", alert)
							c.sendAlert(alert)
							return alert
						}
					}
				}

				// If there is early data, move it into the main buffer
				if c.hsCtx.earlyData != nil {
					c.readBuffer = c.hsCtx.earlyData
					c.hsCtx.earlyData = nil
				}

			} else {
				assert(c.hsCtx.earlyData == nil)
			}
		}

		if c.config.NonBlocking {
			if alert == AlertStatelessRetry {
				return AlertStatelessRetry
			}
			return AlertNoAlert
		}
	}

	return AlertNoAlert
}

func (c *Conn) SendKeyUpdate(requestUpdate bool) error {
	if !c.handshakeComplete {
		return fmt.Errorf("Cannot update keys until after handshake")
	}

	request := KeyUpdateNotRequested
	if requestUpdate {
		request = KeyUpdateRequested
	}

	// Create the key update and update state
	actions, alert := c.state.KeyUpdate(request)
	if alert != AlertNoAlert {
		c.sendAlert(alert)
		return fmt.Errorf("Alert while generating key update: %v", alert)
	}

	// Take actions (send key update and rekey)
	for _, action := range actions {
		alert = c.takeAction(action)
		if alert != AlertNoAlert {
			c.sendAlert(alert)
			return fmt.Errorf("Alert during key update actions: %v", alert)
		}
	}

	return nil
}

func (c *Conn) GetHsState() State {
	if c.hState == nil {
		return StateInit
	}
	return c.hState.State()
}

func (c *Conn) ComputeExporter(label string, context []byte, keyLength int) ([]byte, error) {
	_, connected := c.hState.(stateConnected)
	if !connected {
		return nil, fmt.Errorf("Cannot compute exporter when state is not connected")
	}

	if c.state.exporterSecret == nil {
		return nil, fmt.Errorf("Internal error: no exporter secret")
	}

	h0 := c.state.cryptoParams.Hash.New().Sum(nil)
	tmpSecret := deriveSecret(c.state.cryptoParams, c.state.exporterSecret, label, h0)

	hc := c.state.cryptoParams.Hash.New().Sum(context)
	return HkdfExpandLabel(c.state.cryptoParams.Hash, tmpSecret, "exporter", hc, keyLength), nil
}

func (c *Conn) ConnectionState() ConnectionState {
	state := ConnectionState{
		HandshakeState: c.GetHsState(),
	}

	if c.handshakeComplete {
		state.CipherSuite = cipherSuiteMap[c.state.Params.CipherSuite]
		state.NextProto = c.state.Params.NextProto
		state.VerifiedChains = c.state.verifiedChains
		state.PeerCertificates = c.state.peerCertificates
		state.UsingPSK = c.state.Params.UsingPSK
		state.UsingEarlyData = c.state.Params.UsingEarlyData
	}

	return state
}

func (c *Conn) Writable() bool {
	// If we're connected, we're writable.
	if _, connected := c.hState.(stateConnected); connected {
		return true
	}

	// If we're a client in 0-RTT, then we're writable.
	if c.isClient && c.out.cipher.epoch == EpochEarlyData {
		return true
	}

	return false
}

func (c *Conn) label() string {
	if c.isClient {
		return "client"
	}
	return "server"
}
