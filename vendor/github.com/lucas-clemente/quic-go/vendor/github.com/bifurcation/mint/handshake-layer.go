package mint

import (
	"fmt"
	"io"
	"net"
)

const (
	handshakeHeaderLenTLS  = 4       // handshake message header length
	handshakeHeaderLenDTLS = 12      // handshake message header length
	maxHandshakeMessageLen = 1 << 24 // max handshake message length
)

// struct {
//     HandshakeType msg_type;    /* handshake type */
//     uint24 length;             /* bytes in message */
//     select (HandshakeType) {
//       ...
//     } body;
// } Handshake;
//
// We do the select{...} part in a different layer, so we treat the
// actual message body as opaque:
//
// struct {
//     HandshakeType msg_type;
//     opaque msg<0..2^24-1>
// } Handshake;
//
type HandshakeMessage struct {
	msgType  HandshakeType
	seq      uint32
	body     []byte
	datagram bool
	offset   uint32 // Used for DTLS
	length   uint32
	records  []uint64 // Used for DTLS
	cipher   *cipherState
}

// Note: This could be done with the `syntax` module, using the simplified
// syntax as discussed above.  However, since this is so simple, there's not
// much benefit to doing so.
// When datagram is set, we marshal this as a whole DTLS record.
func (hm *HandshakeMessage) Marshal() []byte {
	if hm == nil {
		return []byte{}
	}

	fragLen := len(hm.body)
	var data []byte

	if hm.datagram {
		data = make([]byte, handshakeHeaderLenDTLS+fragLen)
	} else {
		data = make([]byte, handshakeHeaderLenTLS+fragLen)
	}
	tmp := data
	tmp = encodeUint(uint64(hm.msgType), 1, tmp)
	tmp = encodeUint(uint64(hm.length), 3, tmp)
	if hm.datagram {
		tmp = encodeUint(uint64(hm.seq), 2, tmp)
		tmp = encodeUint(uint64(hm.offset), 3, tmp)
		tmp = encodeUint(uint64(fragLen), 3, tmp)
	}
	copy(tmp, hm.body)
	return data
}

func (hm HandshakeMessage) ToBody() (HandshakeMessageBody, error) {
	logf(logTypeHandshake, "HandshakeMessage.toBody [%d] [%x]", hm.msgType, hm.body)

	var body HandshakeMessageBody
	switch hm.msgType {
	case HandshakeTypeClientHello:
		body = new(ClientHelloBody)
	case HandshakeTypeServerHello:
		body = new(ServerHelloBody)
	case HandshakeTypeEncryptedExtensions:
		body = new(EncryptedExtensionsBody)
	case HandshakeTypeCertificate:
		body = new(CertificateBody)
	case HandshakeTypeCertificateRequest:
		body = new(CertificateRequestBody)
	case HandshakeTypeCertificateVerify:
		body = new(CertificateVerifyBody)
	case HandshakeTypeFinished:
		body = &FinishedBody{VerifyDataLen: len(hm.body)}
	case HandshakeTypeNewSessionTicket:
		body = new(NewSessionTicketBody)
	case HandshakeTypeKeyUpdate:
		body = new(KeyUpdateBody)
	case HandshakeTypeEndOfEarlyData:
		body = new(EndOfEarlyDataBody)
	default:
		return body, fmt.Errorf("tls.handshakemessage: Unsupported body type")
	}

	err := safeUnmarshal(body, hm.body)
	return body, err
}

func (h *HandshakeLayer) HandshakeMessageFromBody(body HandshakeMessageBody) (*HandshakeMessage, error) {
	data, err := body.Marshal()
	if err != nil {
		return nil, err
	}

	m := &HandshakeMessage{
		msgType:  body.Type(),
		body:     data,
		seq:      h.msgSeq,
		datagram: h.datagram,
		length:   uint32(len(data)),
	}
	h.msgSeq++
	return m, nil
}

type HandshakeLayer struct {
	nonblocking    bool                // Should we operate in nonblocking mode
	conn           *RecordLayer        // Used for reading/writing records
	frame          *frameReader        // The buffered frame reader
	datagram       bool                // Is this DTLS?
	msgSeq         uint32              // The DTLS message sequence number
	queued         []*HandshakeMessage // In/out queue
	sent           []*HandshakeMessage // Sent messages for DTLS
	maxFragmentLen int
}

type handshakeLayerFrameDetails struct {
	datagram bool
}

func (d handshakeLayerFrameDetails) headerLen() int {
	if d.datagram {
		return handshakeHeaderLenDTLS
	}
	return handshakeHeaderLenTLS
}

func (d handshakeLayerFrameDetails) defaultReadLen() int {
	return d.headerLen() + maxFragmentLen
}

func (d handshakeLayerFrameDetails) frameLen(hdr []byte) (int, error) {
	logf(logTypeIO, "Header=%x", hdr)
	// The length of this fragment (as opposed to the message)
	// is always the last three bytes for both TLS and DTLS
	val, _ := decodeUint(hdr[len(hdr)-3:], 3)
	return int(val), nil
}

func NewHandshakeLayerTLS(r *RecordLayer) *HandshakeLayer {
	h := HandshakeLayer{}
	h.conn = r
	h.datagram = false
	h.frame = newFrameReader(&handshakeLayerFrameDetails{false})
	h.maxFragmentLen = maxFragmentLen
	return &h
}

func NewHandshakeLayerDTLS(r *RecordLayer) *HandshakeLayer {
	h := HandshakeLayer{}
	h.conn = r
	h.datagram = true
	h.frame = newFrameReader(&handshakeLayerFrameDetails{true})
	h.maxFragmentLen = initialMtu // Not quite right
	return &h
}

func (h *HandshakeLayer) readRecord() error {
	logf(logTypeVerbose, "Trying to read record")
	pt, err := h.conn.ReadRecord()
	if err != nil {
		return err
	}

	if pt.contentType != RecordTypeHandshake &&
		pt.contentType != RecordTypeAlert {
		return fmt.Errorf("tls.handshakelayer: Unexpected record type %d", pt.contentType)
	}

	if pt.contentType == RecordTypeAlert {
		logf(logTypeIO, "read alert %v", pt.fragment[1])
		if len(pt.fragment) < 2 {
			h.sendAlert(AlertUnexpectedMessage)
			return io.EOF
		}
		return Alert(pt.fragment[1])
	}

	h.frame.addChunk(pt.fragment)

	return nil
}

// sendAlert sends a TLS alert message.
func (h *HandshakeLayer) sendAlert(err Alert) error {
	tmp := make([]byte, 2)
	tmp[0] = AlertLevelError
	tmp[1] = byte(err)
	h.conn.WriteRecord(&TLSPlaintext{
		contentType: RecordTypeAlert,
		fragment:    tmp},
	)

	// closeNotify is a special case in that it isn't an error:
	if err != AlertCloseNotify {
		return &net.OpError{Op: "local error", Err: err}
	}
	return nil
}

func (h *HandshakeLayer) noteMessageDelivered(seq uint32) {
	h.msgSeq = seq + 1
	var i int
	var m *HandshakeMessage
	for i, m = range h.queued {
		if m.seq > seq {
			break
		}
	}
	h.queued = h.queued[i:]
}

func (h *HandshakeLayer) newFragmentReceived(hm *HandshakeMessage) (*HandshakeMessage, error) {
	if hm.seq < h.msgSeq {
		return nil, WouldBlock
	}

	if hm.seq == h.msgSeq && hm.offset == 0 && hm.length == uint32(len(hm.body)) {
		// TODO(ekr@rtfm.com): Check the length?
		// This is complete.
		h.noteMessageDelivered(hm.seq)
		return hm, nil
	}

	// Now insert sorted.
	var i int
	for i = 0; i < len(h.queued); i++ {
		f := h.queued[i]
		if hm.seq < f.seq {
			break
		}
		if hm.offset < f.offset {
			break
		}
	}
	tmp := make([]*HandshakeMessage, 0, len(h.queued)+1)
	tmp = append(tmp, h.queued[:i]...)
	tmp = append(tmp, hm)
	tmp = append(tmp, h.queued[i:]...)
	h.queued = tmp

	return h.checkMessageAvailable()
}

func (h *HandshakeLayer) checkMessageAvailable() (*HandshakeMessage, error) {
	if len(h.queued) == 0 {
		return nil, WouldBlock
	}

	hm := h.queued[0]
	if hm.seq != h.msgSeq {
		return nil, WouldBlock
	}

	if hm.seq == h.msgSeq && hm.offset == 0 && hm.length == uint32(len(hm.body)) {
		// TODO(ekr@rtfm.com): Check the length?
		// This is complete.
		h.noteMessageDelivered(hm.seq)
		return hm, nil
	}

	// OK, this at least might complete the message.
	end := uint32(0)
	buf := make([]byte, hm.length)

	for _, f := range h.queued {
		// Out of fragments
		if f.seq > hm.seq {
			break
		}

		if f.length != uint32(len(buf)) {
			return nil, fmt.Errorf("Mismatched DTLS length")
		}

		if f.offset > end {
			break
		}

		if f.offset+uint32(len(f.body)) > end {
			// OK, this is adding something we don't know about
			copy(buf[f.offset:], f.body)
			end = f.offset + uint32(len(f.body))
			if end == hm.length {
				h2 := *hm
				h2.offset = 0
				h2.body = buf
				h.noteMessageDelivered(hm.seq)
				return &h2, nil
			}
		}

	}

	return nil, WouldBlock
}

func (h *HandshakeLayer) ReadMessage() (*HandshakeMessage, error) {
	var hdr, body []byte
	var err error

	hm, err := h.checkMessageAvailable()
	if err == nil {
		return hm, err
	}
	if err != WouldBlock {
		return nil, err
	}
	for {
		logf(logTypeVerbose, "ReadMessage() buffered=%v", len(h.frame.remainder))
		if h.frame.needed() > 0 {
			logf(logTypeVerbose, "Trying to read a new record")
			err = h.readRecord()

			if err != nil && (h.nonblocking || err != WouldBlock) {
				return nil, err
			}
		}

		hdr, body, err = h.frame.process()
		if err == nil {
			break
		}
		if err != nil && (h.nonblocking || err != WouldBlock) {
			return nil, err
		}
	}

	logf(logTypeHandshake, "read handshake message")

	hm = &HandshakeMessage{}
	hm.msgType = HandshakeType(hdr[0])
	hm.datagram = h.datagram
	hm.body = make([]byte, len(body))
	copy(hm.body, body)
	logf(logTypeHandshake, "Read message with type: %v", hm.msgType)
	if h.datagram {
		tmp, hdr := decodeUint(hdr[1:], 3)
		hm.length = uint32(tmp)
		tmp, hdr = decodeUint(hdr, 2)
		hm.seq = uint32(tmp)
		tmp, hdr = decodeUint(hdr, 3)
		hm.offset = uint32(tmp)

		return h.newFragmentReceived(hm)
	}

	hm.length = uint32(len(body))
	return hm, nil
}

func (h *HandshakeLayer) QueueMessage(hm *HandshakeMessage) error {
	hm.cipher = h.conn.cipher
	h.queued = append(h.queued, hm)
	return nil
}

func (h *HandshakeLayer) SendQueuedMessages() error {
	logf(logTypeHandshake, "Sending outgoing messages")
	err := h.WriteMessages(h.queued)
	h.ClearQueuedMessages() // This isn't going to work for DTLS, but we'll
	// get there.
	return err
}

func (h *HandshakeLayer) ClearQueuedMessages() {
	logf(logTypeHandshake, "Clearing outgoing hs message queue")
	h.queued = nil
}

func (h *HandshakeLayer) writeFragment(hm *HandshakeMessage, start int, room int) (int, error) {
	var buf []byte

	// Figure out if we're going to want the full header or just
	// the body
	hdrlen := 0
	if hm.datagram {
		hdrlen = handshakeHeaderLenDTLS
	} else if start == 0 {
		hdrlen = handshakeHeaderLenTLS
	}

	// Compute the amount of body we can fit in
	room -= hdrlen
	if room == 0 {
		// This works because we are doing one record per
		// message
		panic("Too short max fragment len")
	}
	bodylen := len(hm.body) - start
	if bodylen > room {
		bodylen = room
	}
	body := hm.body[start : start+bodylen]

	// Encode the data.
	if hdrlen > 0 {
		hm2 := *hm
		hm2.offset = uint32(start)
		hm2.body = body
		buf = hm2.Marshal()
	} else {
		buf = body
	}

	return start + bodylen, h.conn.writeRecordWithPadding(
		&TLSPlaintext{
			contentType: RecordTypeHandshake,
			fragment:    buf,
		},
		hm.cipher, 0)
}

func (h *HandshakeLayer) WriteMessage(hm *HandshakeMessage) error {
	start := int(0)

	if len(hm.body) > maxHandshakeMessageLen {
		return fmt.Errorf("Tried to write a handshake message that's too long")
	}

	// Always make one pass through to allow EOED (which is empty).
	for {
		var err error
		start, err = h.writeFragment(hm, start, h.maxFragmentLen)
		if err != nil {
			return err
		}
		if start >= len(hm.body) {
			break
		}
	}

	return nil
}

func (h *HandshakeLayer) WriteMessages(hms []*HandshakeMessage) error {
	for _, hm := range hms {
		logf(logTypeHandshake, "WriteMessage [%d] %x", hm.msgType, hm.body)

		err := h.WriteMessage(hm)
		if err != nil {
			return err
		}
	}
	return nil
}

func encodeUint(v uint64, size int, out []byte) []byte {
	for i := size - 1; i >= 0; i-- {
		out[i] = byte(v & 0xff)
		v >>= 8
	}
	return out[size:]
}

func decodeUint(in []byte, size int) (uint64, []byte) {
	val := uint64(0)

	for i := 0; i < size; i++ {
		val <<= 8
		val += uint64(in[i])
	}
	return val, in[size:]
}

type marshalledPDU interface {
	Marshal() ([]byte, error)
	Unmarshal(data []byte) (int, error)
}

func safeUnmarshal(pdu marshalledPDU, data []byte) error {
	read, err := pdu.Unmarshal(data)
	if err != nil {
		return err
	}
	if len(data) != read {
		return fmt.Errorf("Invalid encoding: Extra data not consumed")
	}
	return nil
}
