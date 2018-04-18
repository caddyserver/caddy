package handshake

import (
	"net"

	"github.com/bifurcation/mint"
	"github.com/lucas-clemente/quic-go/internal/utils"
)

// A CookieHandler generates and validates cookies.
// The cookie is sent in the TLS Retry.
// By including the cookie in its ClientHello, a client can proof ownership of its source address.
type CookieHandler struct {
	callback        func(net.Addr, *Cookie) bool
	cookieGenerator *CookieGenerator

	logger utils.Logger
}

var _ mint.CookieHandler = &CookieHandler{}

// NewCookieHandler creates a new CookieHandler.
func NewCookieHandler(callback func(net.Addr, *Cookie) bool, logger utils.Logger) (*CookieHandler, error) {
	cookieGenerator, err := NewCookieGenerator()
	if err != nil {
		return nil, err
	}
	return &CookieHandler{
		callback:        callback,
		cookieGenerator: cookieGenerator,
		logger:          logger,
	}, nil
}

// Generate a new cookie for a mint connection.
func (h *CookieHandler) Generate(conn *mint.Conn) ([]byte, error) {
	if h.callback(conn.RemoteAddr(), nil) {
		return nil, nil
	}
	return h.cookieGenerator.NewToken(conn.RemoteAddr())
}

// Validate a cookie.
func (h *CookieHandler) Validate(conn *mint.Conn, token []byte) bool {
	data, err := h.cookieGenerator.DecodeToken(token)
	if err != nil {
		h.logger.Debugf("Couldn't decode cookie from %s: %s", conn.RemoteAddr(), err.Error())
		return false
	}
	return h.callback(conn.RemoteAddr(), data)
}
