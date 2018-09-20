package h2quic

import (
	"crypto/tls"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strings"
	"sync"

	quic "github.com/lucas-clemente/quic-go"

	"golang.org/x/net/http/httpguts"
)

type roundTripCloser interface {
	http.RoundTripper
	io.Closer
}

// RoundTripper implements the http.RoundTripper interface
type RoundTripper struct {
	mutex sync.Mutex

	// DisableCompression, if true, prevents the Transport from
	// requesting compression with an "Accept-Encoding: gzip"
	// request header when the Request contains no existing
	// Accept-Encoding value. If the Transport requests gzip on
	// its own and gets a gzipped response, it's transparently
	// decoded in the Response.Body. However, if the user
	// explicitly requested gzip it is not automatically
	// uncompressed.
	DisableCompression bool

	// TLSClientConfig specifies the TLS configuration to use with
	// tls.Client. If nil, the default configuration is used.
	TLSClientConfig *tls.Config

	// QuicConfig is the quic.Config used for dialing new connections.
	// If nil, reasonable default values will be used.
	QuicConfig *quic.Config

	// Dial specifies an optional dial function for creating QUIC
	// connections for requests.
	// If Dial is nil, quic.DialAddr will be used.
	Dial func(network, addr string, tlsCfg *tls.Config, cfg *quic.Config) (quic.Session, error)

	clients map[string]roundTripCloser
}

// RoundTripOpt are options for the Transport.RoundTripOpt method.
type RoundTripOpt struct {
	// OnlyCachedConn controls whether the RoundTripper may
	// create a new QUIC connection. If set true and
	// no cached connection is available, RoundTrip
	// will return ErrNoCachedConn.
	OnlyCachedConn bool
}

var _ roundTripCloser = &RoundTripper{}

// ErrNoCachedConn is returned when RoundTripper.OnlyCachedConn is set
var ErrNoCachedConn = errors.New("h2quic: no cached connection was available")

// RoundTripOpt is like RoundTrip, but takes options.
func (r *RoundTripper) RoundTripOpt(req *http.Request, opt RoundTripOpt) (*http.Response, error) {
	if req.URL == nil {
		closeRequestBody(req)
		return nil, errors.New("quic: nil Request.URL")
	}
	if req.URL.Host == "" {
		closeRequestBody(req)
		return nil, errors.New("quic: no Host in request URL")
	}
	if req.Header == nil {
		closeRequestBody(req)
		return nil, errors.New("quic: nil Request.Header")
	}

	if req.URL.Scheme == "https" {
		for k, vv := range req.Header {
			if !httpguts.ValidHeaderFieldName(k) {
				return nil, fmt.Errorf("quic: invalid http header field name %q", k)
			}
			for _, v := range vv {
				if !httpguts.ValidHeaderFieldValue(v) {
					return nil, fmt.Errorf("quic: invalid http header field value %q for key %v", v, k)
				}
			}
		}
	} else {
		closeRequestBody(req)
		return nil, fmt.Errorf("quic: unsupported protocol scheme: %s", req.URL.Scheme)
	}

	if req.Method != "" && !validMethod(req.Method) {
		closeRequestBody(req)
		return nil, fmt.Errorf("quic: invalid method %q", req.Method)
	}

	hostname := authorityAddr("https", hostnameFromRequest(req))
	cl, err := r.getClient(hostname, opt.OnlyCachedConn)
	if err != nil {
		return nil, err
	}
	return cl.RoundTrip(req)
}

// RoundTrip does a round trip.
func (r *RoundTripper) RoundTrip(req *http.Request) (*http.Response, error) {
	return r.RoundTripOpt(req, RoundTripOpt{})
}

func (r *RoundTripper) getClient(hostname string, onlyCached bool) (http.RoundTripper, error) {
	r.mutex.Lock()
	defer r.mutex.Unlock()

	if r.clients == nil {
		r.clients = make(map[string]roundTripCloser)
	}

	client, ok := r.clients[hostname]
	if !ok {
		if onlyCached {
			return nil, ErrNoCachedConn
		}
		client = newClient(
			hostname,
			r.TLSClientConfig,
			&roundTripperOpts{DisableCompression: r.DisableCompression},
			r.QuicConfig,
			r.Dial,
		)
		r.clients[hostname] = client
	}
	return client, nil
}

// Close closes the QUIC connections that this RoundTripper has used
func (r *RoundTripper) Close() error {
	r.mutex.Lock()
	defer r.mutex.Unlock()
	for _, client := range r.clients {
		if err := client.Close(); err != nil {
			return err
		}
	}
	r.clients = nil
	return nil
}

func closeRequestBody(req *http.Request) {
	if req.Body != nil {
		req.Body.Close()
	}
}

func validMethod(method string) bool {
	/*
				     Method         = "OPTIONS"                ; Section 9.2
		   		                    | "GET"                    ; Section 9.3
		   		                    | "HEAD"                   ; Section 9.4
		   		                    | "POST"                   ; Section 9.5
		   		                    | "PUT"                    ; Section 9.6
		   		                    | "DELETE"                 ; Section 9.7
		   		                    | "TRACE"                  ; Section 9.8
		   		                    | "CONNECT"                ; Section 9.9
		   		                    | extension-method
		   		   extension-method = token
		   		     token          = 1*<any CHAR except CTLs or separators>
	*/
	return len(method) > 0 && strings.IndexFunc(method, isNotToken) == -1
}

// copied from net/http/http.go
func isNotToken(r rune) bool {
	return !httpguts.IsTokenRune(r)
}
