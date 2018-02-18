package handshake

import (
	"encoding/asn1"
	"fmt"
	"net"
	"time"

	"github.com/bifurcation/mint"
)

const (
	cookiePrefixIP byte = iota
	cookiePrefixString
)

// A Cookie is derived from the client address and can be used to verify the ownership of this address.
type Cookie struct {
	RemoteAddr string
	// The time that the STK was issued (resolution 1 second)
	SentTime time.Time
}

// token is the struct that is used for ASN1 serialization and deserialization
type token struct {
	Data      []byte
	Timestamp int64
}

// A CookieGenerator generates Cookies
type CookieGenerator struct {
	cookieProtector mint.CookieProtector
}

// NewCookieGenerator initializes a new CookieGenerator
func NewCookieGenerator() (*CookieGenerator, error) {
	cookieProtector, err := mint.NewDefaultCookieProtector()
	if err != nil {
		return nil, err
	}
	return &CookieGenerator{
		cookieProtector: cookieProtector,
	}, nil
}

// NewToken generates a new Cookie for a given source address
func (g *CookieGenerator) NewToken(raddr net.Addr) ([]byte, error) {
	data, err := asn1.Marshal(token{
		Data:      encodeRemoteAddr(raddr),
		Timestamp: time.Now().Unix(),
	})
	if err != nil {
		return nil, err
	}
	return g.cookieProtector.NewToken(data)
}

// DecodeToken decodes a Cookie
func (g *CookieGenerator) DecodeToken(encrypted []byte) (*Cookie, error) {
	// if the client didn't send any Cookie, DecodeToken will be called with a nil-slice
	if len(encrypted) == 0 {
		return nil, nil
	}

	data, err := g.cookieProtector.DecodeToken(encrypted)
	if err != nil {
		return nil, err
	}
	t := &token{}
	rest, err := asn1.Unmarshal(data, t)
	if err != nil {
		return nil, err
	}
	if len(rest) != 0 {
		return nil, fmt.Errorf("rest when unpacking token: %d", len(rest))
	}
	return &Cookie{
		RemoteAddr: decodeRemoteAddr(t.Data),
		SentTime:   time.Unix(t.Timestamp, 0),
	}, nil
}

// encodeRemoteAddr encodes a remote address such that it can be saved in the Cookie
func encodeRemoteAddr(remoteAddr net.Addr) []byte {
	if udpAddr, ok := remoteAddr.(*net.UDPAddr); ok {
		return append([]byte{cookiePrefixIP}, udpAddr.IP...)
	}
	return append([]byte{cookiePrefixString}, []byte(remoteAddr.String())...)
}

// decodeRemoteAddr decodes the remote address saved in the Cookie
func decodeRemoteAddr(data []byte) string {
	// data will never be empty for a Cookie that we generated. Check it to be on the safe side
	if len(data) == 0 {
		return ""
	}
	if data[0] == cookiePrefixIP {
		return net.IP(data[1:]).String()
	}
	return string(data[1:])
}
