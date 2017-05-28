package handshake

import (
	"encoding/asn1"
	"fmt"
	"net"
	"time"

	"github.com/lucas-clemente/quic-go/crypto"
)

const (
	stkPrefixIP byte = iota
	stkPrefixString
)

// An STK is a source address token
type STK struct {
	RemoteAddr string
	SentTime   time.Time
}

// token is the struct that is used for ASN1 serialization and deserialization
type token struct {
	Data      []byte
	Timestamp int64
}

// An STKGenerator generates STKs
type STKGenerator struct {
	stkSource crypto.StkSource
}

// NewSTKGenerator initializes a new STKGenerator
func NewSTKGenerator() (*STKGenerator, error) {
	stkSource, err := crypto.NewStkSource()
	if err != nil {
		return nil, err
	}
	return &STKGenerator{
		stkSource: stkSource,
	}, nil
}

// NewToken generates a new STK token for a given source address
func (g *STKGenerator) NewToken(raddr net.Addr) ([]byte, error) {
	data, err := asn1.Marshal(token{
		Data:      encodeRemoteAddr(raddr),
		Timestamp: time.Now().Unix(),
	})
	if err != nil {
		return nil, err
	}
	return g.stkSource.NewToken(data)
}

// DecodeToken decodes an STK token
func (g *STKGenerator) DecodeToken(encrypted []byte) (*STK, error) {
	// if the client didn't send any STK, DecodeToken will be called with a nil-slice
	if len(encrypted) == 0 {
		return nil, nil
	}

	data, err := g.stkSource.DecodeToken(encrypted)
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
	return &STK{
		RemoteAddr: decodeRemoteAddr(t.Data),
		SentTime:   time.Unix(t.Timestamp, 0),
	}, nil
}

// encodeRemoteAddr encodes a remote address such that it can be saved in the STK
func encodeRemoteAddr(remoteAddr net.Addr) []byte {
	if udpAddr, ok := remoteAddr.(*net.UDPAddr); ok {
		return append([]byte{stkPrefixIP}, udpAddr.IP...)
	}
	return append([]byte{stkPrefixString}, []byte(remoteAddr.String())...)
}

// decodeRemoteAddr decodes the remote address saved in the STK
func decodeRemoteAddr(data []byte) string {
	// data will never be empty for an STK that we generated. Check it to be on the safe side
	if len(data) == 0 {
		return ""
	}
	if data[0] == stkPrefixIP {
		return net.IP(data[1:]).String()
	}
	return string(data[1:])
}
