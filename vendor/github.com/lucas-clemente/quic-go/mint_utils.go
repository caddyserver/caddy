package quic

import (
	"bytes"
	gocrypto "crypto"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"io"

	"github.com/bifurcation/mint"
	"github.com/lucas-clemente/quic-go/internal/crypto"
	"github.com/lucas-clemente/quic-go/internal/handshake"
	"github.com/lucas-clemente/quic-go/internal/protocol"
	"github.com/lucas-clemente/quic-go/internal/utils"
	"github.com/lucas-clemente/quic-go/internal/wire"
)

type mintController struct {
	csc  *handshake.CryptoStreamConn
	conn *mint.Conn
}

var _ handshake.MintTLS = &mintController{}

func newMintController(
	csc *handshake.CryptoStreamConn,
	mconf *mint.Config,
	pers protocol.Perspective,
) handshake.MintTLS {
	var conn *mint.Conn
	if pers == protocol.PerspectiveClient {
		conn = mint.Client(csc, mconf)
	} else {
		conn = mint.Server(csc, mconf)
	}
	return &mintController{
		csc:  csc,
		conn: conn,
	}
}

func (mc *mintController) GetCipherSuite() mint.CipherSuiteParams {
	return mc.conn.ConnectionState().CipherSuite
}

func (mc *mintController) ComputeExporter(label string, context []byte, keyLength int) ([]byte, error) {
	return mc.conn.ComputeExporter(label, context, keyLength)
}

func (mc *mintController) Handshake() mint.Alert {
	return mc.conn.Handshake()
}

func (mc *mintController) State() mint.State {
	return mc.conn.ConnectionState().HandshakeState
}

func (mc *mintController) ConnectionState() mint.ConnectionState {
	return mc.conn.ConnectionState()
}

func (mc *mintController) SetCryptoStream(stream io.ReadWriter) {
	mc.csc.SetStream(stream)
}

func tlsToMintConfig(tlsConf *tls.Config, pers protocol.Perspective) (*mint.Config, error) {
	mconf := &mint.Config{
		NonBlocking: true,
		CipherSuites: []mint.CipherSuite{
			mint.TLS_AES_128_GCM_SHA256,
			mint.TLS_AES_256_GCM_SHA384,
		},
	}
	if tlsConf != nil {
		mconf.ServerName = tlsConf.ServerName
		mconf.InsecureSkipVerify = tlsConf.InsecureSkipVerify
		mconf.Certificates = make([]*mint.Certificate, len(tlsConf.Certificates))
		mconf.VerifyPeerCertificate = tlsConf.VerifyPeerCertificate
		for i, certChain := range tlsConf.Certificates {
			mconf.Certificates[i] = &mint.Certificate{
				Chain:      make([]*x509.Certificate, len(certChain.Certificate)),
				PrivateKey: certChain.PrivateKey.(gocrypto.Signer),
			}
			for j, cert := range certChain.Certificate {
				c, err := x509.ParseCertificate(cert)
				if err != nil {
					return nil, err
				}
				mconf.Certificates[i].Chain[j] = c
			}
		}
		switch tlsConf.ClientAuth {
		case tls.NoClientCert:
		case tls.RequireAnyClientCert:
			mconf.RequireClientAuth = true
		default:
			return nil, errors.New("mint currently only support ClientAuthType RequireAnyClientCert")
		}
	}
	if err := mconf.Init(pers == protocol.PerspectiveClient); err != nil {
		return nil, err
	}
	return mconf, nil
}

// unpackInitialOrRetryPacket unpacks packets Initial and Retry packets
// These packets must contain a STREAM_FRAME for the crypto stream, starting at offset 0.
func unpackInitialPacket(aead crypto.AEAD, hdr *wire.Header, data []byte, version protocol.VersionNumber) (*wire.StreamFrame, error) {
	unpacker := &packetUnpacker{aead: &nullAEAD{aead}, version: version}
	packet, err := unpacker.Unpack(hdr.Raw, hdr, data)
	if err != nil {
		return nil, err
	}
	var frame *wire.StreamFrame
	for _, f := range packet.frames {
		var ok bool
		frame, ok = f.(*wire.StreamFrame)
		if ok {
			break
		}
	}
	if frame == nil {
		return nil, errors.New("Packet doesn't contain a STREAM_FRAME")
	}
	// We don't need a check for the stream ID here.
	// The packetUnpacker checks that there's no unencrypted stream data except for the crypto stream.
	if frame.Offset != 0 {
		return nil, errors.New("received stream data with non-zero offset")
	}
	if utils.Debug() {
		utils.Debugf("<- Reading packet 0x%x (%d bytes) for connection %x", hdr.PacketNumber, len(data)+len(hdr.Raw), hdr.ConnectionID)
		hdr.Log()
		wire.LogFrame(frame, false)
	}
	return frame, nil
}

// packUnencryptedPacket provides a low-overhead way to pack a packet.
// It is supposed to be used in the early stages of the handshake, before a session (which owns a packetPacker) is available.
func packUnencryptedPacket(aead crypto.AEAD, hdr *wire.Header, f wire.Frame, pers protocol.Perspective) ([]byte, error) {
	raw := getPacketBuffer()
	buffer := bytes.NewBuffer(raw)
	if err := hdr.Write(buffer, pers, hdr.Version); err != nil {
		return nil, err
	}
	payloadStartIndex := buffer.Len()
	if err := f.Write(buffer, hdr.Version); err != nil {
		return nil, err
	}
	raw = raw[0:buffer.Len()]
	_ = aead.Seal(raw[payloadStartIndex:payloadStartIndex], raw[payloadStartIndex:], hdr.PacketNumber, raw[:payloadStartIndex])
	raw = raw[0 : buffer.Len()+aead.Overhead()]
	if utils.Debug() {
		utils.Debugf("-> Sending packet 0x%x (%d bytes) for connection %x, %s", hdr.PacketNumber, len(raw), hdr.ConnectionID, protocol.EncryptionUnencrypted)
		hdr.Log()
		wire.LogFrame(f, true)
	}
	return raw, nil
}
