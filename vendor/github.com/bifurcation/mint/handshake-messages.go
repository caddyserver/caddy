package mint

import (
	"bytes"
	"crypto"
	"crypto/x509"
	"encoding/binary"
	"fmt"

	"github.com/bifurcation/mint/syntax"
)

type HandshakeMessageBody interface {
	Type() HandshakeType
	Marshal() ([]byte, error)
	Unmarshal(data []byte) (int, error)
}

// struct {
//     ProtocolVersion legacy_version = 0x0303; /* TLS v1.2 */
//     Random random;
//     opaque legacy_session_id<0..32>;
//     CipherSuite cipher_suites<2..2^16-2>;
//     opaque legacy_compression_methods<1..2^8-1>;
//     Extension extensions<0..2^16-1>;
// } ClientHello;
type ClientHelloBody struct {
	LegacyVersion   uint16
	Random          [32]byte
	LegacySessionID []byte
	CipherSuites    []CipherSuite
	Extensions      ExtensionList
}

type clientHelloBodyInnerTLS struct {
	LegacyVersion            uint16
	Random                   [32]byte
	LegacySessionID          []byte        `tls:"head=1,max=32"`
	CipherSuites             []CipherSuite `tls:"head=2,min=2"`
	LegacyCompressionMethods []byte        `tls:"head=1,min=1"`
	Extensions               []Extension   `tls:"head=2"`
}

type clientHelloBodyInnerDTLS struct {
	LegacyVersion            uint16
	Random                   [32]byte
	LegacySessionID          []byte `tls:"head=1,max=32"`
	EmptyCookie              uint8
	CipherSuites             []CipherSuite `tls:"head=2,min=2"`
	LegacyCompressionMethods []byte        `tls:"head=1,min=1"`
	Extensions               []Extension   `tls:"head=2"`
}

func (ch ClientHelloBody) Type() HandshakeType {
	return HandshakeTypeClientHello
}

func (ch ClientHelloBody) Marshal() ([]byte, error) {
	if ch.LegacyVersion == tls12Version {
		return syntax.Marshal(clientHelloBodyInnerTLS{
			LegacyVersion:            ch.LegacyVersion,
			Random:                   ch.Random,
			LegacySessionID:          []byte{},
			CipherSuites:             ch.CipherSuites,
			LegacyCompressionMethods: []byte{0},
			Extensions:               ch.Extensions,
		})
	} else {
		return syntax.Marshal(clientHelloBodyInnerDTLS{
			LegacyVersion:            ch.LegacyVersion,
			Random:                   ch.Random,
			LegacySessionID:          []byte{},
			CipherSuites:             ch.CipherSuites,
			LegacyCompressionMethods: []byte{0},
			Extensions:               ch.Extensions,
		})
	}

}

func (ch *ClientHelloBody) Unmarshal(data []byte) (int, error) {
	var read int
	var err error

	// Note that this might be 0, in which case we do TLS. That
	// makes the tests easier.
	if ch.LegacyVersion != dtls12WireVersion {
		var inner clientHelloBodyInnerTLS
		read, err = syntax.Unmarshal(data, &inner)
		if err != nil {
			return 0, err
		}

		if len(inner.LegacyCompressionMethods) != 1 || inner.LegacyCompressionMethods[0] != 0 {
			return 0, fmt.Errorf("tls.clienthello: Invalid compression method")
		}

		ch.LegacyVersion = inner.LegacyVersion
		ch.Random = inner.Random
		ch.LegacySessionID = inner.LegacySessionID
		ch.CipherSuites = inner.CipherSuites
		ch.Extensions = inner.Extensions
	} else {
		var inner clientHelloBodyInnerDTLS
		read, err = syntax.Unmarshal(data, &inner)
		if err != nil {
			return 0, err
		}

		if inner.EmptyCookie != 0 {
			return 0, fmt.Errorf("tls.clienthello: Invalid cookie")
		}

		if len(inner.LegacyCompressionMethods) != 1 || inner.LegacyCompressionMethods[0] != 0 {
			return 0, fmt.Errorf("tls.clienthello: Invalid compression method")
		}

		ch.LegacyVersion = inner.LegacyVersion
		ch.Random = inner.Random
		ch.LegacySessionID = inner.LegacySessionID
		ch.CipherSuites = inner.CipherSuites
		ch.Extensions = inner.Extensions
	}
	return read, nil
}

// TODO: File a spec bug to clarify this
func (ch ClientHelloBody) Truncated() ([]byte, error) {
	if len(ch.Extensions) == 0 {
		return nil, fmt.Errorf("tls.clienthello.truncate: No extensions")
	}

	pskExt := ch.Extensions[len(ch.Extensions)-1]
	if pskExt.ExtensionType != ExtensionTypePreSharedKey {
		return nil, fmt.Errorf("tls.clienthello.truncate: Last extension is not PSK")
	}

	body, err := ch.Marshal()
	if err != nil {
		return nil, err
	}
	chm := &HandshakeMessage{
		msgType: ch.Type(),
		body:    body,
		length:  uint32(len(body)),
	}
	chData := chm.Marshal()

	psk := PreSharedKeyExtension{
		HandshakeType: HandshakeTypeClientHello,
	}
	_, err = psk.Unmarshal(pskExt.ExtensionData)
	if err != nil {
		return nil, err
	}

	// Marshal just the binders so that we know how much to truncate
	binders := struct {
		Binders []PSKBinderEntry `tls:"head=2,min=33"`
	}{Binders: psk.Binders}
	binderData, _ := syntax.Marshal(binders)
	binderLen := len(binderData)

	chLen := len(chData)
	return chData[:chLen-binderLen], nil
}

// struct {
//     ProtocolVersion legacy_version = 0x0303;    /* TLS v1.2 */
//     Random random;
//     opaque legacy_session_id_echo<0..32>;
//     CipherSuite cipher_suite;
//     uint8 legacy_compression_method = 0;
//     Extension extensions<6..2^16-1>;
// } ServerHello;
type ServerHelloBody struct {
	Version                 uint16
	Random                  [32]byte
	LegacySessionID         []byte `tls:"head=1,max=32"`
	CipherSuite             CipherSuite
	LegacyCompressionMethod uint8
	Extensions              ExtensionList `tls:"head=2"`
}

func (sh ServerHelloBody) Type() HandshakeType {
	return HandshakeTypeServerHello
}

func (sh ServerHelloBody) Marshal() ([]byte, error) {
	return syntax.Marshal(sh)
}

func (sh *ServerHelloBody) Unmarshal(data []byte) (int, error) {
	return syntax.Unmarshal(data, sh)
}

// struct {
//     opaque verify_data[verify_data_length];
// } Finished;
//
// verifyDataLen is not a field in the TLS struct, but we add it here so
// that calling code can tell us how much data to expect when we marshal /
// unmarshal.  (We could add this to the marshal/unmarshal methods, but let's
// try to keep the signature consistent for now.)
//
// For similar reasons, we don't use the `syntax` module here, because this
// struct doesn't map well to standard TLS presentation language concepts.
//
// TODO: File a spec bug
type FinishedBody struct {
	VerifyDataLen int
	VerifyData    []byte
}

func (fin FinishedBody) Type() HandshakeType {
	return HandshakeTypeFinished
}

func (fin FinishedBody) Marshal() ([]byte, error) {
	if len(fin.VerifyData) != fin.VerifyDataLen {
		return nil, fmt.Errorf("tls.finished: data length mismatch")
	}

	body := make([]byte, len(fin.VerifyData))
	copy(body, fin.VerifyData)
	return body, nil
}

func (fin *FinishedBody) Unmarshal(data []byte) (int, error) {
	if len(data) < fin.VerifyDataLen {
		return 0, fmt.Errorf("tls.finished: Malformed finished; too short")
	}

	fin.VerifyData = make([]byte, fin.VerifyDataLen)
	copy(fin.VerifyData, data[:fin.VerifyDataLen])
	return fin.VerifyDataLen, nil
}

// struct {
//     Extension extensions<0..2^16-1>;
// } EncryptedExtensions;
//
// Marshal() and Unmarshal() are handled by ExtensionList
type EncryptedExtensionsBody struct {
	Extensions ExtensionList `tls:"head=2"`
}

func (ee EncryptedExtensionsBody) Type() HandshakeType {
	return HandshakeTypeEncryptedExtensions
}

func (ee EncryptedExtensionsBody) Marshal() ([]byte, error) {
	return syntax.Marshal(ee)
}

func (ee *EncryptedExtensionsBody) Unmarshal(data []byte) (int, error) {
	return syntax.Unmarshal(data, ee)
}

// opaque ASN1Cert<1..2^24-1>;
//
// struct {
//     ASN1Cert cert_data;
//     Extension extensions<0..2^16-1>
// } CertificateEntry;
//
// struct {
//     opaque certificate_request_context<0..2^8-1>;
//     CertificateEntry certificate_list<0..2^24-1>;
// } Certificate;
type CertificateEntry struct {
	CertData   *x509.Certificate
	Extensions ExtensionList
}

type CertificateBody struct {
	CertificateRequestContext []byte
	CertificateList           []CertificateEntry
}

type certificateEntryInner struct {
	CertData   []byte        `tls:"head=3,min=1"`
	Extensions ExtensionList `tls:"head=2"`
}

type certificateBodyInner struct {
	CertificateRequestContext []byte                  `tls:"head=1"`
	CertificateList           []certificateEntryInner `tls:"head=3"`
}

func (c CertificateBody) Type() HandshakeType {
	return HandshakeTypeCertificate
}

func (c CertificateBody) Marshal() ([]byte, error) {
	inner := certificateBodyInner{
		CertificateRequestContext: c.CertificateRequestContext,
		CertificateList:           make([]certificateEntryInner, len(c.CertificateList)),
	}

	for i, entry := range c.CertificateList {
		inner.CertificateList[i] = certificateEntryInner{
			CertData:   entry.CertData.Raw,
			Extensions: entry.Extensions,
		}
	}

	return syntax.Marshal(inner)
}

func (c *CertificateBody) Unmarshal(data []byte) (int, error) {
	inner := certificateBodyInner{}
	read, err := syntax.Unmarshal(data, &inner)
	if err != nil {
		return read, err
	}

	c.CertificateRequestContext = inner.CertificateRequestContext
	c.CertificateList = make([]CertificateEntry, len(inner.CertificateList))

	for i, entry := range inner.CertificateList {
		c.CertificateList[i].CertData, err = x509.ParseCertificate(entry.CertData)
		if err != nil {
			return 0, fmt.Errorf("tls:certificate: Certificate failed to parse: %v", err)
		}

		c.CertificateList[i].Extensions = entry.Extensions
	}

	return read, nil
}

// struct {
//     SignatureScheme algorithm;
//     opaque signature<0..2^16-1>;
// } CertificateVerify;
type CertificateVerifyBody struct {
	Algorithm SignatureScheme
	Signature []byte `tls:"head=2"`
}

func (cv CertificateVerifyBody) Type() HandshakeType {
	return HandshakeTypeCertificateVerify
}

func (cv CertificateVerifyBody) Marshal() ([]byte, error) {
	return syntax.Marshal(cv)
}

func (cv *CertificateVerifyBody) Unmarshal(data []byte) (int, error) {
	return syntax.Unmarshal(data, cv)
}

func (cv *CertificateVerifyBody) EncodeSignatureInput(data []byte) []byte {
	// TODO: Change context for client auth
	// TODO: Put this in a const
	const context = "TLS 1.3, server CertificateVerify"
	sigInput := bytes.Repeat([]byte{0x20}, 64)
	sigInput = append(sigInput, []byte(context)...)
	sigInput = append(sigInput, []byte{0}...)
	sigInput = append(sigInput, data...)
	return sigInput
}

func (cv *CertificateVerifyBody) Sign(privateKey crypto.Signer, handshakeHash []byte) (err error) {
	sigInput := cv.EncodeSignatureInput(handshakeHash)
	cv.Signature, err = sign(cv.Algorithm, privateKey, sigInput)
	logf(logTypeHandshake, "Signed: alg=[%04x] sigInput=[%x], sig=[%x]", cv.Algorithm, sigInput, cv.Signature)
	return
}

func (cv *CertificateVerifyBody) Verify(publicKey crypto.PublicKey, handshakeHash []byte) error {
	sigInput := cv.EncodeSignatureInput(handshakeHash)
	logf(logTypeHandshake, "About to verify: alg=[%04x] sigInput=[%x], sig=[%x]", cv.Algorithm, sigInput, cv.Signature)
	return verify(cv.Algorithm, publicKey, sigInput, cv.Signature)
}

// struct {
//     opaque certificate_request_context<0..2^8-1>;
//     Extension extensions<2..2^16-1>;
// } CertificateRequest;
type CertificateRequestBody struct {
	CertificateRequestContext []byte        `tls:"head=1"`
	Extensions                ExtensionList `tls:"head=2"`
}

func (cr CertificateRequestBody) Type() HandshakeType {
	return HandshakeTypeCertificateRequest
}

func (cr CertificateRequestBody) Marshal() ([]byte, error) {
	return syntax.Marshal(cr)
}

func (cr *CertificateRequestBody) Unmarshal(data []byte) (int, error) {
	return syntax.Unmarshal(data, cr)
}

// struct {
//     uint32 ticket_lifetime;
//     uint32 ticket_age_add;
//		 opaque ticket_nonce<1..255>;
//     opaque ticket<1..2^16-1>;
//     Extension extensions<0..2^16-2>;
// } NewSessionTicket;
type NewSessionTicketBody struct {
	TicketLifetime uint32
	TicketAgeAdd   uint32
	TicketNonce    []byte        `tls:"head=1,min=1"`
	Ticket         []byte        `tls:"head=2,min=1"`
	Extensions     ExtensionList `tls:"head=2"`
}

const ticketNonceLen = 16

func NewSessionTicket(ticketLen int, ticketLifetime uint32) (*NewSessionTicketBody, error) {
	buf := make([]byte, 4+ticketNonceLen+ticketLen)
	_, err := prng.Read(buf)
	if err != nil {
		return nil, err
	}

	tkt := &NewSessionTicketBody{
		TicketLifetime: ticketLifetime,
		TicketAgeAdd:   binary.BigEndian.Uint32(buf[:4]),
		TicketNonce:    buf[4 : 4+ticketNonceLen],
		Ticket:         buf[4+ticketNonceLen:],
	}

	return tkt, err
}

func (tkt NewSessionTicketBody) Type() HandshakeType {
	return HandshakeTypeNewSessionTicket
}

func (tkt NewSessionTicketBody) Marshal() ([]byte, error) {
	return syntax.Marshal(tkt)
}

func (tkt *NewSessionTicketBody) Unmarshal(data []byte) (int, error) {
	return syntax.Unmarshal(data, tkt)
}

// enum {
//     update_not_requested(0), update_requested(1), (255)
// } KeyUpdateRequest;
//
// struct {
//     KeyUpdateRequest request_update;
// } KeyUpdate;
type KeyUpdateBody struct {
	KeyUpdateRequest KeyUpdateRequest
}

func (ku KeyUpdateBody) Type() HandshakeType {
	return HandshakeTypeKeyUpdate
}

func (ku KeyUpdateBody) Marshal() ([]byte, error) {
	return syntax.Marshal(ku)
}

func (ku *KeyUpdateBody) Unmarshal(data []byte) (int, error) {
	return syntax.Unmarshal(data, ku)
}

// struct {} EndOfEarlyData;
type EndOfEarlyDataBody struct{}

func (eoed EndOfEarlyDataBody) Type() HandshakeType {
	return HandshakeTypeEndOfEarlyData
}

func (eoed EndOfEarlyDataBody) Marshal() ([]byte, error) {
	return []byte{}, nil
}

func (eoed *EndOfEarlyDataBody) Unmarshal(data []byte) (int, error) {
	return 0, nil
}
