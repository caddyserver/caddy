package mint

import (
	"bytes"
	"crypto/cipher"
	"fmt"
	"io"
	"sync"
)

const (
	sequenceNumberLen = 8       // sequence number length
	recordHeaderLen   = 5       // record header length
	maxFragmentLen    = 1 << 14 // max number of bytes in a record
)

type DecryptError string

func (err DecryptError) Error() string {
	return string(err)
}

// struct {
//     ContentType type;
//     ProtocolVersion record_version = { 3, 1 };    /* TLS v1.x */
//     uint16 length;
//     opaque fragment[TLSPlaintext.length];
// } TLSPlaintext;
type TLSPlaintext struct {
	// Omitted: record_version (static)
	// Omitted: length         (computed from fragment)
	contentType RecordType
	fragment    []byte
}

type RecordLayer struct {
	sync.Mutex

	conn         io.ReadWriter // The underlying connection
	frame        *frameReader  // The buffered frame reader
	nextData     []byte        // The next record to send
	cachedRecord *TLSPlaintext // Last record read, cached to enable "peek"
	cachedError  error         // Error on the last record read

	ivLength int         // Length of the seq and nonce fields
	seq      []byte      // Zero-padded sequence number
	nonce    []byte      // Buffer for per-record nonces
	cipher   cipher.AEAD // AEAD cipher
}

type recordLayerFrameDetails struct{}

func (d recordLayerFrameDetails) headerLen() int {
	return recordHeaderLen
}

func (d recordLayerFrameDetails) defaultReadLen() int {
	return recordHeaderLen + maxFragmentLen
}

func (d recordLayerFrameDetails) frameLen(hdr []byte) (int, error) {
	return (int(hdr[3]) << 8) | int(hdr[4]), nil
}

func NewRecordLayer(conn io.ReadWriter) *RecordLayer {
	r := RecordLayer{}
	r.conn = conn
	r.frame = newFrameReader(recordLayerFrameDetails{})
	r.ivLength = 0
	return &r
}

func (r *RecordLayer) Rekey(cipher aeadFactory, key []byte, iv []byte) error {
	var err error
	r.cipher, err = cipher(key)
	if err != nil {
		return err
	}

	r.ivLength = len(iv)
	r.seq = bytes.Repeat([]byte{0}, r.ivLength)
	r.nonce = make([]byte, r.ivLength)
	copy(r.nonce, iv)
	return nil
}

func (r *RecordLayer) incrementSequenceNumber() {
	if r.ivLength == 0 {
		return
	}

	for i := r.ivLength - 1; i > r.ivLength-sequenceNumberLen; i-- {
		r.seq[i]++
		r.nonce[i] ^= (r.seq[i] - 1) ^ r.seq[i]
		if r.seq[i] != 0 {
			return
		}
	}

	// Not allowed to let sequence number wrap.
	// Instead, must renegotiate before it does.
	// Not likely enough to bother.
	panic("TLS: sequence number wraparound")
}

func (r *RecordLayer) encrypt(pt *TLSPlaintext, padLen int) *TLSPlaintext {
	// Expand the fragment to hold contentType, padding, and overhead
	originalLen := len(pt.fragment)
	plaintextLen := originalLen + 1 + padLen
	ciphertextLen := plaintextLen + r.cipher.Overhead()

	// Assemble the revised plaintext
	out := &TLSPlaintext{
		contentType: RecordTypeApplicationData,
		fragment:    make([]byte, ciphertextLen),
	}
	copy(out.fragment, pt.fragment)
	out.fragment[originalLen] = byte(pt.contentType)
	for i := 1; i <= padLen; i++ {
		out.fragment[originalLen+i] = 0
	}

	// Encrypt the fragment
	payload := out.fragment[:plaintextLen]
	r.cipher.Seal(payload[:0], r.nonce, payload, nil)
	return out
}

func (r *RecordLayer) decrypt(pt *TLSPlaintext) (*TLSPlaintext, int, error) {
	if len(pt.fragment) < r.cipher.Overhead() {
		msg := fmt.Sprintf("tls.record.decrypt: Record too short [%d] < [%d]", len(pt.fragment), r.cipher.Overhead())
		return nil, 0, DecryptError(msg)
	}

	decryptLen := len(pt.fragment) - r.cipher.Overhead()
	out := &TLSPlaintext{
		contentType: pt.contentType,
		fragment:    make([]byte, decryptLen),
	}

	// Decrypt
	_, err := r.cipher.Open(out.fragment[:0], r.nonce, pt.fragment, nil)
	if err != nil {
		return nil, 0, DecryptError("tls.record.decrypt: AEAD decrypt failed")
	}

	// Find the padding boundary
	padLen := 0
	for ; padLen < decryptLen+1 && out.fragment[decryptLen-padLen-1] == 0; padLen++ {
	}

	// Transfer the content type
	newLen := decryptLen - padLen - 1
	out.contentType = RecordType(out.fragment[newLen])

	// Truncate the message to remove contentType, padding, overhead
	out.fragment = out.fragment[:newLen]
	return out, padLen, nil
}

func (r *RecordLayer) PeekRecordType(block bool) (RecordType, error) {
	var pt *TLSPlaintext
	var err error

	for {
		pt, err = r.nextRecord()
		if err == nil {
			break
		}
		if !block || err != WouldBlock {
			return 0, err
		}
	}
	return pt.contentType, nil
}

func (r *RecordLayer) ReadRecord() (*TLSPlaintext, error) {
	pt, err := r.nextRecord()

	// Consume the cached record if there was one
	r.cachedRecord = nil
	r.cachedError = nil

	return pt, err
}

func (r *RecordLayer) nextRecord() (*TLSPlaintext, error) {
	if r.cachedRecord != nil {
		logf(logTypeIO, "Returning cached record")
		return r.cachedRecord, r.cachedError
	}

	// Loop until one of three things happens:
	//
	// 1. We get a frame
	// 2. We try to read off the socket and get nothing, in which case
	//    return WouldBlock
	// 3. We get an error.
	err := WouldBlock
	var header, body []byte

	for err != nil {
		if r.frame.needed() > 0 {
			buf := make([]byte, recordHeaderLen+maxFragmentLen)
			n, err := r.conn.Read(buf)
			if err != nil {
				logf(logTypeIO, "Error reading, %v", err)
				return nil, err
			}

			if n == 0 {
				return nil, WouldBlock
			}

			logf(logTypeIO, "Read %v bytes", n)

			buf = buf[:n]
			r.frame.addChunk(buf)
		}

		header, body, err = r.frame.process()
		// Loop around on WouldBlock to see if some
		// data is now available.
		if err != nil && err != WouldBlock {
			return nil, err
		}
	}

	pt := &TLSPlaintext{}
	// Validate content type
	switch RecordType(header[0]) {
	default:
		return nil, fmt.Errorf("tls.record: Unknown content type %02x", header[0])
	case RecordTypeAlert, RecordTypeHandshake, RecordTypeApplicationData:
		pt.contentType = RecordType(header[0])
	}

	// Validate version
	if !allowWrongVersionNumber && (header[1] != 0x03 || header[2] != 0x01) {
		return nil, fmt.Errorf("tls.record: Invalid version %02x%02x", header[1], header[2])
	}

	// Validate size < max
	size := (int(header[3]) << 8) + int(header[4])
	if size > maxFragmentLen+256 {
		return nil, fmt.Errorf("tls.record: Ciphertext size too big")
	}

	pt.fragment = make([]byte, size)
	copy(pt.fragment, body)

	// Attempt to decrypt fragment
	if r.cipher != nil {
		pt, _, err = r.decrypt(pt)
		if err != nil {
			return nil, err
		}
	}

	// Check that plaintext length is not too long
	if len(pt.fragment) > maxFragmentLen {
		return nil, fmt.Errorf("tls.record: Plaintext size too big")
	}

	logf(logTypeIO, "RecordLayer.ReadRecord [%d] [%x]", pt.contentType, pt.fragment)

	r.cachedRecord = pt
	r.incrementSequenceNumber()
	return pt, nil
}

func (r *RecordLayer) WriteRecord(pt *TLSPlaintext) error {
	return r.WriteRecordWithPadding(pt, 0)
}

func (r *RecordLayer) WriteRecordWithPadding(pt *TLSPlaintext, padLen int) error {
	if r.cipher != nil {
		pt = r.encrypt(pt, padLen)
	} else if padLen > 0 {
		return fmt.Errorf("tls.record: Padding can only be done on encrypted records")
	}

	if len(pt.fragment) > maxFragmentLen {
		return fmt.Errorf("tls.record: Record size too big")
	}

	length := len(pt.fragment)
	header := []byte{byte(pt.contentType), 0x03, 0x01, byte(length >> 8), byte(length)}
	record := append(header, pt.fragment...)

	logf(logTypeIO, "RecordLayer.WriteRecord [%d] [%x]", pt.contentType, pt.fragment)

	r.incrementSequenceNumber()
	_, err := r.conn.Write(record)
	return err
}
