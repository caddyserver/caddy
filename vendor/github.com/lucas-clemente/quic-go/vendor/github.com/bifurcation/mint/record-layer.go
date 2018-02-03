package mint

import (
	"bytes"
	"crypto/cipher"
	"fmt"
	"io"
	"sync"
)

const (
	sequenceNumberLen   = 8       // sequence number length
	recordHeaderLenTLS  = 5       // record header length (TLS)
	recordHeaderLenDTLS = 13      // record header length (DTLS)
	maxFragmentLen      = 1 << 14 // max number of bytes in a record
)

type DecryptError string

func (err DecryptError) Error() string {
	return string(err)
}

// struct {
//     ContentType type;
//     ProtocolVersion record_version [0301 for CH, 0303 for others]
//     uint16 length;
//     opaque fragment[TLSPlaintext.length];
// } TLSPlaintext;
type TLSPlaintext struct {
	// Omitted: record_version (static)
	// Omitted: length         (computed from fragment)
	contentType RecordType
	fragment    []byte
}

type cipherState struct {
	epoch    Epoch       // DTLS epoch
	ivLength int         // Length of the seq and nonce fields
	seq      []byte      // Zero-padded sequence number
	iv       []byte      // Buffer for the IV
	cipher   cipher.AEAD // AEAD cipher
}

type RecordLayer struct {
	sync.Mutex

	version      uint16        // The current version number
	conn         io.ReadWriter // The underlying connection
	frame        *frameReader  // The buffered frame reader
	nextData     []byte        // The next record to send
	cachedRecord *TLSPlaintext // Last record read, cached to enable "peek"
	cachedError  error         // Error on the last record read

	cipher   *cipherState
	datagram bool
}

type recordLayerFrameDetails struct {
	datagram bool
}

func (d recordLayerFrameDetails) headerLen() int {
	if d.datagram {
		return recordHeaderLenDTLS
	}
	return recordHeaderLenTLS
}

func (d recordLayerFrameDetails) defaultReadLen() int {
	return d.headerLen() + maxFragmentLen
}

func (d recordLayerFrameDetails) frameLen(hdr []byte) (int, error) {
	return (int(hdr[d.headerLen()-2]) << 8) | int(hdr[d.headerLen()-1]), nil
}

func newCipherStateNull() *cipherState {
	return &cipherState{EpochClear, 0, bytes.Repeat([]byte{0}, sequenceNumberLen), nil, nil}
}

func newCipherStateAead(epoch Epoch, factory aeadFactory, key []byte, iv []byte) (*cipherState, error) {
	cipher, err := factory(key)
	if err != nil {
		return nil, err
	}

	return &cipherState{epoch, len(iv), bytes.Repeat([]byte{0}, sequenceNumberLen), iv, cipher}, nil
}

func NewRecordLayerTLS(conn io.ReadWriter) *RecordLayer {
	r := RecordLayer{}
	r.conn = conn
	r.frame = newFrameReader(recordLayerFrameDetails{false})
	r.cipher = newCipherStateNull()
	r.version = tls10Version
	return &r
}

func NewRecordLayerDTLS(conn io.ReadWriter) *RecordLayer {
	r := RecordLayer{}
	r.conn = conn
	r.frame = newFrameReader(recordLayerFrameDetails{true})
	r.cipher = newCipherStateNull()
	r.datagram = true
	return &r
}

func (r *RecordLayer) SetVersion(v uint16) {
	r.version = v
}

func (r *RecordLayer) Rekey(epoch Epoch, factory aeadFactory, key []byte, iv []byte) error {
	cipher, err := newCipherStateAead(epoch, factory, key, iv)
	if err != nil {
		return err
	}
	r.cipher = cipher
	return nil
}

func (c *cipherState) formatSeq(datagram bool) []byte {
	seq := append([]byte{}, c.seq...)
	if datagram {
		seq[0] = byte(c.epoch >> 8)
		seq[1] = byte(c.epoch & 0xff)
	}
	return seq
}

func (c *cipherState) computeNonce(seq []byte) []byte {
	nonce := make([]byte, len(c.iv))
	copy(nonce, c.iv)

	offset := len(c.iv) - len(seq)
	for i, b := range seq {
		nonce[i+offset] ^= b
	}

	return nonce
}

func (c *cipherState) incrementSequenceNumber() {
	var i int
	for i = len(c.seq) - 1; i >= 0; i-- {
		c.seq[i]++
		if c.seq[i] != 0 {
			break
		}
	}

	if i < 0 {
		// Not allowed to let sequence number wrap.
		// Instead, must renegotiate before it does.
		// Not likely enough to bother.
		// TODO(ekr@rtfm.com): Check for DTLS here
		// because the limit is sooner.
		panic("TLS: sequence number wraparound")
	}
}

func (c *cipherState) overhead() int {
	if c.cipher == nil {
		return 0
	}
	return c.cipher.Overhead()
}

func (r *RecordLayer) encrypt(cipher *cipherState, seq []byte, pt *TLSPlaintext, padLen int) *TLSPlaintext {
	logf(logTypeIO, "Encrypt seq=[%x]", seq)
	// Expand the fragment to hold contentType, padding, and overhead
	originalLen := len(pt.fragment)
	plaintextLen := originalLen + 1 + padLen
	ciphertextLen := plaintextLen + cipher.overhead()

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
	cipher.cipher.Seal(payload[:0], cipher.computeNonce(seq), payload, nil)
	return out
}

func (r *RecordLayer) decrypt(pt *TLSPlaintext, seq []byte) (*TLSPlaintext, int, error) {
	logf(logTypeIO, "Decrypt seq=[%x]", seq)
	if len(pt.fragment) < r.cipher.overhead() {
		msg := fmt.Sprintf("tls.record.decrypt: Record too short [%d] < [%d]", len(pt.fragment), r.cipher.overhead())
		return nil, 0, DecryptError(msg)
	}

	decryptLen := len(pt.fragment) - r.cipher.overhead()
	out := &TLSPlaintext{
		contentType: pt.contentType,
		fragment:    make([]byte, decryptLen),
	}

	// Decrypt
	_, err := r.cipher.cipher.Open(out.fragment[:0], r.cipher.computeNonce(seq), pt.fragment, nil)
	if err != nil {
		logf(logTypeIO, "AEAD decryption failure [%x]", pt)
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
	cipher := r.cipher
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
			buf := make([]byte, r.frame.details.headerLen()+maxFragmentLen)
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
	size := (int(header[len(header)-2]) << 8) + int(header[len(header)-1])

	if size > maxFragmentLen+256 {
		return nil, fmt.Errorf("tls.record: Ciphertext size too big")
	}

	pt.fragment = make([]byte, size)
	copy(pt.fragment, body)

	// Attempt to decrypt fragment
	if cipher.cipher != nil {
		seq := cipher.seq
		if r.datagram {
			seq = header[3:11]
		}
		// TODO(ekr@rtfm.com): Handle the wrong epoch.
		// TODO(ekr@rtfm.com): Handle duplicates.
		logf(logTypeIO, "RecordLayer.ReadRecord epoch=[%s] seq=[%x] [%d] ciphertext=[%x]", cipher.epoch.label(), seq, pt.contentType, pt.fragment)
		pt, _, err = r.decrypt(pt, seq)
		if err != nil {
			logf(logTypeIO, "Decryption failed")
			return nil, err
		}
	}

	// Check that plaintext length is not too long
	if len(pt.fragment) > maxFragmentLen {
		return nil, fmt.Errorf("tls.record: Plaintext size too big")
	}

	logf(logTypeIO, "RecordLayer.ReadRecord [%d] [%x]", pt.contentType, pt.fragment)

	r.cachedRecord = pt
	cipher.incrementSequenceNumber()
	return pt, nil
}

func (r *RecordLayer) WriteRecord(pt *TLSPlaintext) error {
	return r.writeRecordWithPadding(pt, r.cipher, 0)
}

func (r *RecordLayer) WriteRecordWithPadding(pt *TLSPlaintext, padLen int) error {
	return r.writeRecordWithPadding(pt, r.cipher, padLen)
}

func (r *RecordLayer) writeRecordWithPadding(pt *TLSPlaintext, cipher *cipherState, padLen int) error {
	seq := cipher.formatSeq(r.datagram)

	if cipher.cipher != nil {
		logf(logTypeIO, "RecordLayer.WriteRecord epoch=[%s] seq=[%x] [%d] plaintext=[%x]", cipher.epoch.label(), cipher.seq, pt.contentType, pt.fragment)
		pt = r.encrypt(cipher, seq, pt, padLen)
	} else if padLen > 0 {
		return fmt.Errorf("tls.record: Padding can only be done on encrypted records")
	}

	if len(pt.fragment) > maxFragmentLen {
		return fmt.Errorf("tls.record: Record size too big")
	}

	length := len(pt.fragment)
	var header []byte

	if !r.datagram {
		header = []byte{byte(pt.contentType),
			byte(r.version >> 8), byte(r.version & 0xff),
			byte(length >> 8), byte(length)}
	} else {
		version := dtlsConvertVersion(r.version)
		header = []byte{byte(pt.contentType),
			byte(version >> 8), byte(version & 0xff),
			seq[0], seq[1], seq[2], seq[3],
			seq[4], seq[5], seq[6], seq[7],
			byte(length >> 8), byte(length)}
	}
	record := append(header, pt.fragment...)

	logf(logTypeIO, "RecordLayer.WriteRecord epoch=[%s] seq=[%x] [%d] ciphertext=[%x]", cipher.epoch.label(), cipher.seq, pt.contentType, pt.fragment)

	cipher.incrementSequenceNumber()
	_, err := r.conn.Write(record)
	return err
}
