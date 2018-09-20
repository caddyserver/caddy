package quic

import (
	"bytes"

	"github.com/lucas-clemente/quic-go/internal/protocol"
	"github.com/lucas-clemente/quic-go/internal/wire"
	"github.com/lucas-clemente/quic-go/qerr"
)

type unpackedPacket struct {
	encryptionLevel protocol.EncryptionLevel
	frames          []wire.Frame
}

type gQUICAEAD interface {
	Open(dst, src []byte, packetNumber protocol.PacketNumber, associatedData []byte) ([]byte, protocol.EncryptionLevel, error)
}

type quicAEAD interface {
	OpenHandshake(dst, src []byte, packetNumber protocol.PacketNumber, associatedData []byte) ([]byte, error)
	Open1RTT(dst, src []byte, packetNumber protocol.PacketNumber, associatedData []byte) ([]byte, error)
}

type packetUnpackerBase struct {
	version protocol.VersionNumber
}

func (u *packetUnpackerBase) parseFrames(decrypted []byte, hdr *wire.Header) ([]wire.Frame, error) {
	r := bytes.NewReader(decrypted)
	if r.Len() == 0 {
		return nil, qerr.MissingPayload
	}

	fs := make([]wire.Frame, 0, 2)
	// Read all frames in the packet
	for {
		frame, err := wire.ParseNextFrame(r, hdr, u.version)
		if err != nil {
			return nil, err
		}
		if frame == nil {
			break
		}
		fs = append(fs, frame)
	}
	return fs, nil
}

// The packetUnpackerGQUIC unpacks gQUIC packets.
type packetUnpackerGQUIC struct {
	packetUnpackerBase
	aead gQUICAEAD
}

var _ unpacker = &packetUnpackerGQUIC{}

func newPacketUnpackerGQUIC(aead gQUICAEAD, version protocol.VersionNumber) unpacker {
	return &packetUnpackerGQUIC{
		packetUnpackerBase: packetUnpackerBase{version: version},
		aead:               aead,
	}
}

func (u *packetUnpackerGQUIC) Unpack(headerBinary []byte, hdr *wire.Header, data []byte) (*unpackedPacket, error) {
	decrypted, encryptionLevel, err := u.aead.Open(data[:0], data, hdr.PacketNumber, headerBinary)
	if err != nil {
		// Wrap err in quicError so that public reset is sent by session
		return nil, qerr.Error(qerr.DecryptionFailure, err.Error())
	}

	fs, err := u.parseFrames(decrypted, hdr)
	if err != nil {
		return nil, err
	}

	return &unpackedPacket{
		encryptionLevel: encryptionLevel,
		frames:          fs,
	}, nil
}

// The packetUnpacker unpacks IETF QUIC packets.
type packetUnpacker struct {
	packetUnpackerBase
	aead quicAEAD
}

var _ unpacker = &packetUnpacker{}

func newPacketUnpacker(aead quicAEAD, version protocol.VersionNumber) unpacker {
	return &packetUnpacker{
		packetUnpackerBase: packetUnpackerBase{version: version},
		aead:               aead,
	}
}

func (u *packetUnpacker) Unpack(headerBinary []byte, hdr *wire.Header, data []byte) (*unpackedPacket, error) {
	buf := *getPacketBuffer()
	buf = buf[:0]
	defer putPacketBuffer(&buf)

	var decrypted []byte
	var encryptionLevel protocol.EncryptionLevel
	var err error
	if hdr.IsLongHeader {
		decrypted, err = u.aead.OpenHandshake(buf, data, hdr.PacketNumber, headerBinary)
		encryptionLevel = protocol.EncryptionUnencrypted
	} else {
		decrypted, err = u.aead.Open1RTT(buf, data, hdr.PacketNumber, headerBinary)
		encryptionLevel = protocol.EncryptionForwardSecure
	}
	if err != nil {
		// Wrap err in quicError so that public reset is sent by session
		return nil, qerr.Error(qerr.DecryptionFailure, err.Error())
	}

	fs, err := u.parseFrames(decrypted, hdr)
	if err != nil {
		return nil, err
	}

	return &unpackedPacket{
		encryptionLevel: encryptionLevel,
		frames:          fs,
	}, nil
}
