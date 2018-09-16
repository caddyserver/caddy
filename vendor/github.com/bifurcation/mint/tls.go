package mint

// XXX(rlb): This file is borrowed pretty much wholesale from crypto/tls

import (
	"errors"
	"net"
	"strings"
	"time"
)

// Server returns a new TLS server side connection
// using conn as the underlying transport.
// The configuration config must be non-nil and must include
// at least one certificate or else set GetCertificate.
func Server(conn net.Conn, config *Config) *Conn {
	return NewConn(conn, config, false)
}

// Client returns a new TLS client side connection
// using conn as the underlying transport.
// The config cannot be nil: users must set either ServerName or
// InsecureSkipVerify in the config.
func Client(conn net.Conn, config *Config) *Conn {
	return NewConn(conn, config, true)
}

// A listener implements a network listener (net.Listener) for TLS connections.
type Listener struct {
	net.Listener
	config *Config
}

// Accept waits for and returns the next incoming TLS connection.
// The returned connection c is a *tls.Conn.
func (l *Listener) Accept() (c net.Conn, err error) {
	c, err = l.Listener.Accept()
	if err != nil {
		return
	}
	server := Server(c, l.config)
	err = server.Handshake()
	if err == AlertNoAlert {
		err = nil
	}
	c = server
	return
}

// NewListener creates a Listener which accepts connections from an inner
// Listener and wraps each connection with Server.
// The configuration config must be non-nil and must include
// at least one certificate or else set GetCertificate.
func NewListener(inner net.Listener, config *Config) (net.Listener, error) {
	if config != nil && config.NonBlocking {
		return nil, errors.New("listening not possible in non-blocking mode")
	}
	l := new(Listener)
	l.Listener = inner
	l.config = config
	return l, nil
}

// Listen creates a TLS listener accepting connections on the
// given network address using net.Listen.
// The configuration config must be non-nil and must include
// at least one certificate or else set GetCertificate.
func Listen(network, laddr string, config *Config) (net.Listener, error) {
	if config == nil || !config.ValidForServer() {
		return nil, errors.New("tls: neither Certificates nor GetCertificate set in Config")
	}
	l, err := net.Listen(network, laddr)
	if err != nil {
		return nil, err
	}
	return NewListener(l, config)
}

type TimeoutError struct{}

func (TimeoutError) Error() string   { return "tls: DialWithDialer timed out" }
func (TimeoutError) Timeout() bool   { return true }
func (TimeoutError) Temporary() bool { return true }

// DialWithDialer connects to the given network address using dialer.Dial and
// then initiates a TLS handshake, returning the resulting TLS connection. Any
// timeout or deadline given in the dialer apply to connection and TLS
// handshake as a whole.
//
// DialWithDialer interprets a nil configuration as equivalent to the zero
// configuration; see the documentation of Config for the defaults.
func DialWithDialer(dialer *net.Dialer, network, addr string, config *Config) (*Conn, error) {
	if config != nil && config.NonBlocking {
		return nil, errors.New("dialing not possible in non-blocking mode")
	}

	// We want the Timeout and Deadline values from dialer to cover the
	// whole process: TCP connection and TLS handshake. This means that we
	// also need to start our own timers now.
	timeout := dialer.Timeout

	if !dialer.Deadline.IsZero() {
		deadlineTimeout := dialer.Deadline.Sub(time.Now())
		if timeout == 0 || deadlineTimeout < timeout {
			timeout = deadlineTimeout
		}
	}

	var errChannel chan error

	if timeout != 0 {
		errChannel = make(chan error, 2)
		time.AfterFunc(timeout, func() {
			errChannel <- TimeoutError{}
		})
	}

	rawConn, err := dialer.Dial(network, addr)
	if err != nil {
		return nil, err
	}

	colonPos := strings.LastIndex(addr, ":")
	if colonPos == -1 {
		colonPos = len(addr)
	}
	hostname := addr[:colonPos]

	if config == nil {
		config = &Config{}
	} else {
		config = config.Clone()
	}

	// If no ServerName is set, infer the ServerName
	// from the hostname we're connecting to.
	if config.ServerName == "" {
		config.ServerName = hostname

	}

	// Set up DTLS as needed.
	config.UseDTLS = (network == "udp")

	conn := Client(rawConn, config)

	if timeout == 0 {
		err = conn.Handshake()
		if err == AlertNoAlert {
			err = nil
		}
	} else {
		go func() {
			errChannel <- conn.Handshake()
		}()

		err = <-errChannel
		if err == AlertNoAlert {
			err = nil
		}
	}

	if err != nil {
		rawConn.Close()
		return nil, err
	}

	return conn, nil
}

// Dial connects to the given network address using net.Dial
// and then initiates a TLS handshake, returning the resulting
// TLS connection.
// Dial interprets a nil configuration as equivalent to
// the zero configuration; see the documentation of Config
// for the defaults.
func Dial(network, addr string, config *Config) (*Conn, error) {
	return DialWithDialer(new(net.Dialer), network, addr, config)
}
