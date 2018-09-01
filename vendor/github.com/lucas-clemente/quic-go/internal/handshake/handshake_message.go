package handshake

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"io"
	"sort"

	"github.com/lucas-clemente/quic-go/internal/protocol"
	"github.com/lucas-clemente/quic-go/internal/utils"
	"github.com/lucas-clemente/quic-go/qerr"
)

// A HandshakeMessage is a handshake message
type HandshakeMessage struct {
	Tag  Tag
	Data map[Tag][]byte
}

var _ fmt.Stringer = &HandshakeMessage{}

// ParseHandshakeMessage reads a crypto message
func ParseHandshakeMessage(r io.Reader) (HandshakeMessage, error) {
	slice4 := make([]byte, 4)

	if _, err := io.ReadFull(r, slice4); err != nil {
		return HandshakeMessage{}, err
	}
	messageTag := Tag(binary.LittleEndian.Uint32(slice4))

	if _, err := io.ReadFull(r, slice4); err != nil {
		return HandshakeMessage{}, err
	}
	nPairs := binary.LittleEndian.Uint32(slice4)

	if nPairs > protocol.CryptoMaxParams {
		return HandshakeMessage{}, qerr.CryptoTooManyEntries
	}

	index := make([]byte, nPairs*8)
	if _, err := io.ReadFull(r, index); err != nil {
		return HandshakeMessage{}, err
	}

	resultMap := map[Tag][]byte{}

	var dataStart uint32
	for indexPos := 0; indexPos < int(nPairs)*8; indexPos += 8 {
		tag := Tag(binary.LittleEndian.Uint32(index[indexPos : indexPos+4]))
		dataEnd := binary.LittleEndian.Uint32(index[indexPos+4 : indexPos+8])

		dataLen := dataEnd - dataStart
		if dataLen > protocol.CryptoParameterMaxLength {
			return HandshakeMessage{}, qerr.Error(qerr.CryptoInvalidValueLength, "value too long")
		}

		data := make([]byte, dataLen)
		if _, err := io.ReadFull(r, data); err != nil {
			return HandshakeMessage{}, err
		}

		resultMap[tag] = data
		dataStart = dataEnd
	}

	return HandshakeMessage{
		Tag:  messageTag,
		Data: resultMap}, nil
}

// Write writes a crypto message
func (h HandshakeMessage) Write(b *bytes.Buffer) {
	data := h.Data
	utils.LittleEndian.WriteUint32(b, uint32(h.Tag))
	utils.LittleEndian.WriteUint16(b, uint16(len(data)))
	utils.LittleEndian.WriteUint16(b, 0)

	// Save current position in the buffer, so that we can update the index in-place later
	indexStart := b.Len()

	indexData := make([]byte, 8*len(data))
	b.Write(indexData) // Will be updated later

	offset := uint32(0)
	for i, t := range h.getTagsSorted() {
		v := data[t]
		b.Write(v)
		offset += uint32(len(v))
		binary.LittleEndian.PutUint32(indexData[i*8:], uint32(t))
		binary.LittleEndian.PutUint32(indexData[i*8+4:], offset)
	}

	// Now we write the index data for real
	copy(b.Bytes()[indexStart:], indexData)
}

func (h *HandshakeMessage) getTagsSorted() []Tag {
	tags := make([]Tag, len(h.Data))
	i := 0
	for t := range h.Data {
		tags[i] = t
		i++
	}
	sort.Slice(tags, func(i, j int) bool {
		return tags[i] < tags[j]
	})
	return tags
}

func (h HandshakeMessage) String() string {
	var pad string
	res := tagToString(h.Tag) + ":\n"
	for _, tag := range h.getTagsSorted() {
		if tag == TagPAD {
			pad = fmt.Sprintf("\t%s: (%d bytes)\n", tagToString(tag), len(h.Data[tag]))
		} else {
			res += fmt.Sprintf("\t%s: %#v\n", tagToString(tag), string(h.Data[tag]))
		}
	}

	if len(pad) > 0 {
		res += pad
	}
	return res
}

func tagToString(tag Tag) string {
	b := make([]byte, 4)
	binary.LittleEndian.PutUint32(b, uint32(tag))
	for i := range b {
		if b[i] == 0 {
			b[i] = ' '
		}
	}
	return string(b)
}
