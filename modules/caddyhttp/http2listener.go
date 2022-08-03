package caddyhttp

import (
	"context"
	"crypto/tls"
	"math/rand"
	"net"
	"net/http"
	"sync/atomic"
	"time"

	"golang.org/x/net/http2"
)

type http2Listener struct {
	cnt uint64
	net.Listener
	server   *http.Server
	h2server *http2.Server
}

type connectionStateConn interface {
	net.Conn
	ConnectionState() tls.ConnectionState
}

func (h *http2Listener) Accept() (net.Conn, error) {
	for {
		conn, err := h.Listener.Accept()
		if err != nil {
			return nil, err
		}

		if csc, ok := conn.(connectionStateConn); ok {
			// *tls.Conn will return empty string because it's only populated after handshake is complete
			if csc.ConnectionState().NegotiatedProtocol == http2.NextProtoTLS {
				go h.serveHttp2(csc)
				continue
			}
		}

		return conn, nil
	}
}

func (h *http2Listener) serveHttp2(csc connectionStateConn) {
	atomic.AddUint64(&h.cnt, 1)
	defer atomic.AddUint64(&h.cnt, ^uint64(0))
	h.h2server.ServeConn(csc, &http2.ServeConnOpts{
		Context:    h.server.ConnContext(context.Background(), csc),
		BaseConfig: h.server,
		Handler:    h.server.Handler,
	})
}

const shutdownPollIntervalMax = 500 * time.Millisecond

func (h *http2Listener) Shutdown(ctx context.Context) error {
	pollIntervalBase := time.Millisecond
	nextPollInterval := func() time.Duration {
		// Add 10% jitter.
		interval := pollIntervalBase + time.Duration(rand.Intn(int(pollIntervalBase/10)))
		// Double and clamp for next time.
		pollIntervalBase *= 2
		if pollIntervalBase > shutdownPollIntervalMax {
			pollIntervalBase = shutdownPollIntervalMax
		}
		return interval
	}

	timer := time.NewTimer(nextPollInterval())
	defer timer.Stop()
	for {
		if atomic.LoadUint64(&h.cnt) == 0 {
			return nil
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-timer.C:
			timer.Reset(nextPollInterval())
		}
	}
}
