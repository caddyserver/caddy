package wire

import (
	"bytes"
	"encoding/binary"
	"errors"

	"github.com/lucas-clemente/quic-go/internal/handshake"
	"github.com/lucas-clemente/quic-go/internal/protocol"
	"github.com/lucas-clemente/quic-go/internal/utils"
)

// A PublicReset is a PUBLIC_RESET
type PublicReset struct {
	RejectedPacketNumber protocol.PacketNumber
	Nonce                uint64
}

// WritePublicReset writes a PUBLIC_RESET
func WritePublicReset(connectionID protocol.ConnectionID, rejectedPacketNumber protocol.PacketNumber, nonceProof uint64) []byte {
	b := &bytes.Buffer{}
	b.WriteByte(0x0a)
	b.Write(connectionID)
	utils.LittleEndian.WriteUint32(b, uint32(handshake.TagPRST))
	utils.LittleEndian.WriteUint32(b, 2)
	utils.LittleEndian.WriteUint32(b, uint32(handshake.TagRNON))
	utils.LittleEndian.WriteUint32(b, 8)
	utils.LittleEndian.WriteUint32(b, uint32(handshake.TagRSEQ))
	utils.LittleEndian.WriteUint32(b, 16)
	utils.LittleEndian.WriteUint64(b, nonceProof)
	utils.LittleEndian.WriteUint64(b, uint64(rejectedPacketNumber))
	return b.Bytes()
}

// ParsePublicReset parses a PUBLIC_RESET
func ParsePublicReset(r *bytes.Reader) (*PublicReset, error) {
	pr := PublicReset{}
	msg, err := handshake.ParseHandshakeMessage(r)
	if err != nil {
		return nil, err
	}
	if msg.Tag != handshake.TagPRST {
		return nil, errors.New("wrong public reset tag")
	}

	// The RSEQ tag is mandatory according to the gQUIC wire spec.
	// However, Google doesn't send RSEQ in their PUBLIC_RESETs.
	// Therefore, we'll treat RSEQ as an optional field.
	if rseq, ok := msg.Data[handshake.TagRSEQ]; ok {
		if len(rseq) != 8 {
			return nil, errors.New("invalid RSEQ tag")
		}
		pr.RejectedPacketNumber = protocol.PacketNumber(binary.LittleEndian.Uint64(rseq))
	}

	rnon, ok := msg.Data[handshake.TagRNON]
	if !ok {
		return nil, errors.New("RNON missing")
	}
	if len(rnon) != 8 {
		return nil, errors.New("invalid RNON tag")
	}
	pr.Nonce = binary.LittleEndian.Uint64(rnon)
	return &pr, nil
}
