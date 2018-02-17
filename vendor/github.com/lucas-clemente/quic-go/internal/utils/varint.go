package utils

import (
	"bytes"
	"fmt"
	"io"

	"github.com/lucas-clemente/quic-go/internal/protocol"
)

// taken from the QUIC draft
const (
	maxVarInt1 = 63
	maxVarInt2 = 16383
	maxVarInt4 = 1073741823
	maxVarInt8 = 4611686018427387903
)

// ReadVarInt reads a number in the QUIC varint format
func ReadVarInt(b io.ByteReader) (uint64, error) {
	firstByte, err := b.ReadByte()
	if err != nil {
		return 0, err
	}
	// the first two bits of the first byte encode the length
	len := 1 << ((firstByte & 0xc0) >> 6)
	b1 := firstByte & (0xff - 0xc0)
	if len == 1 {
		return uint64(b1), nil
	}
	b2, err := b.ReadByte()
	if err != nil {
		return 0, err
	}
	if len == 2 {
		return uint64(b2) + uint64(b1)<<8, nil
	}
	b3, err := b.ReadByte()
	if err != nil {
		return 0, err
	}
	b4, err := b.ReadByte()
	if err != nil {
		return 0, err
	}
	if len == 4 {
		return uint64(b4) + uint64(b3)<<8 + uint64(b2)<<16 + uint64(b1)<<24, nil
	}
	b5, err := b.ReadByte()
	if err != nil {
		return 0, err
	}
	b6, err := b.ReadByte()
	if err != nil {
		return 0, err
	}
	b7, err := b.ReadByte()
	if err != nil {
		return 0, err
	}
	b8, err := b.ReadByte()
	if err != nil {
		return 0, err
	}
	return uint64(b8) + uint64(b7)<<8 + uint64(b6)<<16 + uint64(b5)<<24 + uint64(b4)<<32 + uint64(b3)<<40 + uint64(b2)<<48 + uint64(b1)<<56, nil
}

// WriteVarInt writes a number in the QUIC varint format
func WriteVarInt(b *bytes.Buffer, i uint64) {
	if i <= maxVarInt1 {
		b.WriteByte(uint8(i))
	} else if i <= maxVarInt2 {
		b.Write([]byte{uint8(i>>8) | 0x40, uint8(i)})
	} else if i <= maxVarInt4 {
		b.Write([]byte{uint8(i>>24) | 0x80, uint8(i >> 16), uint8(i >> 8), uint8(i)})
	} else if i <= maxVarInt8 {
		b.Write([]byte{
			uint8(i>>56) | 0xc0, uint8(i >> 48), uint8(i >> 40), uint8(i >> 32),
			uint8(i >> 24), uint8(i >> 16), uint8(i >> 8), uint8(i),
		})
	} else {
		panic(fmt.Sprintf("%#x doesn't fit into 62 bits", i))
	}
}

// VarIntLen determines the number of bytes that will be needed to write a number
func VarIntLen(i uint64) protocol.ByteCount {
	if i <= maxVarInt1 {
		return 1
	}
	if i <= maxVarInt2 {
		return 2
	}
	if i <= maxVarInt4 {
		return 4
	}
	if i <= maxVarInt8 {
		return 8
	}
	panic(fmt.Sprintf("%#x doesn't fit into 62 bits", i))
}
