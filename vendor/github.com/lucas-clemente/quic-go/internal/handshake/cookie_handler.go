package handshake

import (
	"net"

	"github.com/bifurcation/mint"
	"github.com/lucas-clemente/quic-go/internal/utils"
)

type CookieHandler struct {
	callback func(net.Addr, *Cookie) bool

	cookieGenerator *CookieGenerator
}

var _ mint.CookieHandler = &CookieHandler{}

func NewCookieHandler(callback func(net.Addr, *Cookie) bool) (*CookieHandler, error) {
	cookieGenerator, err := NewCookieGenerator()
	if err != nil {
		return nil, err
	}
	return &CookieHandler{
		callback:        callback,
		cookieGenerator: cookieGenerator,
	}, nil
}

func (h *CookieHandler) Generate(conn *mint.Conn) ([]byte, error) {
	if h.callback(conn.RemoteAddr(), nil) {
		return nil, nil
	}
	return h.cookieGenerator.NewToken(conn.RemoteAddr())
}

func (h *CookieHandler) Validate(conn *mint.Conn, token []byte) bool {
	data, err := h.cookieGenerator.DecodeToken(token)
	if err != nil {
		utils.Debugf("Couldn't decode cookie from %s: %s", conn.RemoteAddr(), err.Error())
		return false
	}
	return h.callback(conn.RemoteAddr(), data)
}
