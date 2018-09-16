package mint

import (
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

type direction uint8

const (
	directionWrite = direction(1)
	directionRead  = direction(2)
)

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
	epoch       Epoch
	seq         uint64
	fragment    []byte
}

type cipherState struct {
	epoch    Epoch       // DTLS epoch
	ivLength int         // Length of the seq and nonce fields
	seq      uint64      // Zero-padded sequence number
	iv       []byte      // Buffer for the IV
	cipher   cipher.AEAD // AEAD cipher
}

type RecordLayer struct {
	sync.Mutex
	label        string
	direction    direction
	version      uint16        // The current version number
	conn         io.ReadWriter // The underlying connection
	frame        *frameReader  // The buffered frame reader
	nextData     []byte        // The next record to send
	cachedRecord *TLSPlaintext // Last record read, cached to enable "peek"
	cachedError  error         // Error on the last record read

	cipher      *cipherState
	readCiphers map[Epoch]*cipherState

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
	return &cipherState{EpochClear, 0, 0, nil, nil}
}

func newCipherStateAead(epoch Epoch, factory aeadFactory, key []byte, iv []byte) (*cipherState, error) {
	cipher, err := factory(key)
	if err != nil {
		return nil, err
	}

	return &cipherState{epoch, len(iv), 0, iv, cipher}, nil
}

func NewRecordLayerTLS(conn io.ReadWriter, dir direction) *RecordLayer {
	r := RecordLayer{}
	r.label = ""
	r.direction = dir
	r.conn = conn
	r.frame = newFrameReader(recordLayerFrameDetails{false})
	r.cipher = newCipherStateNull()
	r.version = tls10Version
	return &r
}

func NewRecordLayerDTLS(conn io.ReadWriter, dir direction) *RecordLayer {
	r := RecordLayer{}
	r.label = ""
	r.direction = dir
	r.conn = conn
	r.frame = newFrameReader(recordLayerFrameDetails{true})
	r.cipher = newCipherStateNull()
	r.readCiphers = make(map[Epoch]*cipherState, 0)
	r.readCiphers[0] = r.cipher
	r.datagram = true
	return &r
}

func (r *RecordLayer) SetVersion(v uint16) {
	r.version = v
}

func (r *RecordLayer) ResetClear(seq uint64) {
	r.cipher = newCipherStateNull()
	r.cipher.seq = seq
}

func (r *RecordLayer) Rekey(epoch Epoch, factory aeadFactory, key []byte, iv []byte) error {
	cipher, err := newCipherStateAead(epoch, factory, key, iv)
	if err != nil {
		return err
	}
	r.cipher = cipher
	if r.datagram && r.direction == directionRead {
		r.readCiphers[epoch] = cipher
	}
	return nil
}

// TODO(ekr@rtfm.com): This is never used, which is a bug.
func (r *RecordLayer) DiscardReadKey(epoch Epoch) {
	if !r.datagram {
		return
	}

	_, ok := r.readCiphers[epoch]
	assert(ok)
	delete(r.readCiphers, epoch)
}

func (c *cipherState) combineSeq(datagram bool) uint64 {
	seq := c.seq
	if datagram {
		seq |= uint64(c.epoch) << 48
	}
	return seq
}

func (c *cipherState) computeNonce(seq uint64) []byte {
	nonce := make([]byte, len(c.iv))
	copy(nonce, c.iv)

	s := seq

	offset := len(c.iv)
	for i := 0; i < 8; i++ {
		nonce[(offset-i)-1] ^= byte(s & 0xff)
		s >>= 8
	}
	logf(logTypeCrypto, "Computing nonce for sequence # %x -> %x", seq, nonce)

	return nonce
}

func (c *cipherState) incrementSequenceNumber() {
	if c.seq >= (1<<48 - 1) {
		// Not allowed to let sequence number wrap.
		// Instead, must renegotiate before it does.
		// Not likely enough to bother. This is the
		// DTLS limit.
		panic("TLS: sequence number wraparound")
	}
	c.seq++
}

func (c *cipherState) overhead() int {
	if c.cipher == nil {
		return 0
	}
	return c.cipher.Overhead()
}

func (r *RecordLayer) encrypt(cipher *cipherState, seq uint64, pt *TLSPlaintext, padLen int) *TLSPlaintext {
	assert(r.direction == directionWrite)
	logf(logTypeIO, "%s Encrypt seq=[%x]", r.label, seq)
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

func (r *RecordLayer) decrypt(pt *TLSPlaintext, seq uint64) (*TLSPlaintext, int, error) {
	assert(r.direction == directionRead)
	logf(logTypeIO, "%s Decrypt seq=[%x]", r.label, seq)
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
		logf(logTypeIO, "%s AEAD decryption failure [%x]", r.label, pt)
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
	out.seq = seq
	return out, padLen, nil
}

func (r *RecordLayer) PeekRecordType(block bool) (RecordType, error) {
	var pt *TLSPlaintext
	var err error

	for {
		pt, err = r.nextRecord(false)
		if err == nil {
			break
		}
		if !block || err != AlertWouldBlock {
			return 0, err
		}
	}
	return pt.contentType, nil
}

func (r *RecordLayer) ReadRecord() (*TLSPlaintext, error) {
	pt, err := r.nextRecord(false)

	// Consume the cached record if there was one
	r.cachedRecord = nil
	r.cachedError = nil

	return pt, err
}

func (r *RecordLayer) readRecordAnyEpoch() (*TLSPlaintext, error) {
	pt, err := r.nextRecord(true)

	// Consume the cached record if there was one
	r.cachedRecord = nil
	r.cachedError = nil

	return pt, err
}

func (r *RecordLayer) nextRecord(allowOldEpoch bool) (*TLSPlaintext, error) {
	cipher := r.cipher
	if r.cachedRecord != nil {
		logf(logTypeIO, "%s Returning cached record", r.label)
		return r.cachedRecord, r.cachedError
	}

	// Loop until one of three things happens:
	//
	// 1. We get a frame
	// 2. We try to read off the socket and get nothing, in which case
	//    returnAlertWouldBlock
	// 3. We get an error.
	var err error
	err = AlertWouldBlock
	var header, body []byte

	for err != nil {
		if r.frame.needed() > 0 {
			buf := make([]byte, r.frame.details.headerLen()+maxFragmentLen)
			n, err := r.conn.Read(buf)
			if err != nil {
				logf(logTypeIO, "%s Error reading, %v", r.label, err)
				return nil, err
			}

			if n == 0 {
				return nil, AlertWouldBlock
			}

			logf(logTypeIO, "%s Read %v bytes", r.label, n)

			buf = buf[:n]
			r.frame.addChunk(buf)
		}

		header, body, err = r.frame.process()
		// Loop around onAlertWouldBlock to see if some
		// data is now available.
		if err != nil && err != AlertWouldBlock {
			return nil, err
		}
	}

	pt := &TLSPlaintext{}
	// Validate content type
	switch RecordType(header[0]) {
	default:
		return nil, fmt.Errorf("tls.record: Unknown content type %02x", header[0])
	case RecordTypeAlert, RecordTypeHandshake, RecordTypeApplicationData, RecordTypeAck:
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

	// TODO(ekr@rtfm.com): Enforce that for epoch > 0, the content type is app data.

	// Attempt to decrypt fragment
	seq := cipher.seq
	if r.datagram {
		// TODO(ekr@rtfm.com): Handle duplicates.
		seq, _ = decodeUint(header[3:11], 8)
		epoch := Epoch(seq >> 48)

		// Look up the cipher suite from the epoch
		c, ok := r.readCiphers[epoch]
		if !ok {
			logf(logTypeIO, "%s Message from unknown epoch: [%v]", r.label, epoch)
			return nil, AlertWouldBlock
		}

		if epoch != cipher.epoch {
			logf(logTypeIO, "%s Message from non-current epoch: [%v != %v] out-of-epoch reads=%v", r.label, epoch,
				cipher.epoch, allowOldEpoch)
			if !allowOldEpoch {
				return nil, AlertWouldBlock
			}
			cipher = c
		}
	}

	if cipher.cipher != nil {
		logf(logTypeIO, "%s RecordLayer.ReadRecord epoch=[%s] seq=[%x] [%d] ciphertext=[%x]", r.label, cipher.epoch.label(), seq, pt.contentType, pt.fragment)
		pt, _, err = r.decrypt(pt, seq)
		if err != nil {
			logf(logTypeIO, "%s Decryption failed", r.label)
			return nil, err
		}
	}
	pt.epoch = cipher.epoch

	// Check that plaintext length is not too long
	if len(pt.fragment) > maxFragmentLen {
		return nil, fmt.Errorf("tls.record: Plaintext size too big")
	}

	logf(logTypeIO, "%s RecordLayer.ReadRecord [%d] [%x]", r.label, pt.contentType, pt.fragment)

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
	seq := cipher.combineSeq(r.datagram)
	if cipher.cipher != nil {
		logf(logTypeIO, "%s RecordLayer.WriteRecord epoch=[%s] seq=[%x] [%d] plaintext=[%x]", r.label, cipher.epoch.label(), cipher.seq, pt.contentType, pt.fragment)
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
		header = make([]byte, 13)
		version := dtlsConvertVersion(r.version)
		copy(header, []byte{byte(pt.contentType),
			byte(version >> 8), byte(version & 0xff),
		})
		encodeUint(seq, 8, header[3:])
		encodeUint(uint64(length), 2, header[11:])
	}
	record := append(header, pt.fragment...)

	logf(logTypeIO, "%s RecordLayer.WriteRecord epoch=[%s] seq=[%x] [%d] ciphertext=[%x]", r.label, cipher.epoch.label(), cipher.seq, pt.contentType, pt.fragment)

	cipher.incrementSequenceNumber()
	_, err := r.conn.Write(record)
	return err
}
