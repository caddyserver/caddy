package mint

import (
	"fmt"
	"strconv"
)

const (
	supportedVersion  uint16 = 0x7f16 // draft-22
	tls12Version      uint16 = 0x0303
	tls10Version      uint16 = 0x0301
	dtls12WireVersion uint16 = 0xfefd
)

var (
	// Flags for some minor compat issues
	allowWrongVersionNumber = true
	allowPKCS1              = true
)

// enum {...} ContentType;
type RecordType byte

const (
	RecordTypeAlert           RecordType = 21
	RecordTypeHandshake       RecordType = 22
	RecordTypeApplicationData RecordType = 23
	RecordTypeAck             RecordType = 25
)

// enum {...} HandshakeType;
type HandshakeType byte

const (
	// Omitted: *_RESERVED
	HandshakeTypeClientHello         HandshakeType = 1
	HandshakeTypeServerHello         HandshakeType = 2
	HandshakeTypeNewSessionTicket    HandshakeType = 4
	HandshakeTypeEndOfEarlyData      HandshakeType = 5
	HandshakeTypeHelloRetryRequest   HandshakeType = 6
	HandshakeTypeEncryptedExtensions HandshakeType = 8
	HandshakeTypeCertificate         HandshakeType = 11
	HandshakeTypeCertificateRequest  HandshakeType = 13
	HandshakeTypeCertificateVerify   HandshakeType = 15
	HandshakeTypeServerConfiguration HandshakeType = 17
	HandshakeTypeFinished            HandshakeType = 20
	HandshakeTypeKeyUpdate           HandshakeType = 24
	HandshakeTypeMessageHash         HandshakeType = 254
)

var hrrRandomSentinel = [32]byte{
	0xcf, 0x21, 0xad, 0x74, 0xe5, 0x9a, 0x61, 0x11,
	0xbe, 0x1d, 0x8c, 0x02, 0x1e, 0x65, 0xb8, 0x91,
	0xc2, 0xa2, 0x11, 0x16, 0x7a, 0xbb, 0x8c, 0x5e,
	0x07, 0x9e, 0x09, 0xe2, 0xc8, 0xa8, 0x33, 0x9c,
}

// uint8 CipherSuite[2];
type CipherSuite uint16

const (
	// XXX: Actually TLS_NULL_WITH_NULL_NULL, but we need a way to label the zero
	// value for this type so that we can detect when a field is set.
	CIPHER_SUITE_UNKNOWN         CipherSuite = 0x0000
	TLS_AES_128_GCM_SHA256       CipherSuite = 0x1301
	TLS_AES_256_GCM_SHA384       CipherSuite = 0x1302
	TLS_CHACHA20_POLY1305_SHA256 CipherSuite = 0x1303
	TLS_AES_128_CCM_SHA256       CipherSuite = 0x1304
	TLS_AES_256_CCM_8_SHA256     CipherSuite = 0x1305
)

func (c CipherSuite) String() string {
	switch c {
	case CIPHER_SUITE_UNKNOWN:
		return "unknown"
	case TLS_AES_128_GCM_SHA256:
		return "TLS_AES_128_GCM_SHA256"
	case TLS_AES_256_GCM_SHA384:
		return "TLS_AES_256_GCM_SHA384"
	case TLS_CHACHA20_POLY1305_SHA256:
		return "TLS_CHACHA20_POLY1305_SHA256"
	case TLS_AES_128_CCM_SHA256:
		return "TLS_AES_128_CCM_SHA256"
	case TLS_AES_256_CCM_8_SHA256:
		return "TLS_AES_256_CCM_8_SHA256"
	}
	// cannot use %x here, since it calls String(), leading to infinite recursion
	return fmt.Sprintf("invalid CipherSuite value: 0x%s", strconv.FormatUint(uint64(c), 16))
}

// enum {...} SignatureScheme
type SignatureScheme uint16

const (
	// RSASSA-PKCS1-v1_5 algorithms
	RSA_PKCS1_SHA1   SignatureScheme = 0x0201
	RSA_PKCS1_SHA256 SignatureScheme = 0x0401
	RSA_PKCS1_SHA384 SignatureScheme = 0x0501
	RSA_PKCS1_SHA512 SignatureScheme = 0x0601
	// ECDSA algorithms
	ECDSA_P256_SHA256 SignatureScheme = 0x0403
	ECDSA_P384_SHA384 SignatureScheme = 0x0503
	ECDSA_P521_SHA512 SignatureScheme = 0x0603
	// RSASSA-PSS algorithms
	RSA_PSS_SHA256 SignatureScheme = 0x0804
	RSA_PSS_SHA384 SignatureScheme = 0x0805
	RSA_PSS_SHA512 SignatureScheme = 0x0806
	// EdDSA algorithms
	Ed25519 SignatureScheme = 0x0807
	Ed448   SignatureScheme = 0x0808
)

// enum {...} ExtensionType
type ExtensionType uint16

const (
	ExtensionTypeServerName          ExtensionType = 0
	ExtensionTypeSupportedGroups     ExtensionType = 10
	ExtensionTypeSignatureAlgorithms ExtensionType = 13
	ExtensionTypeALPN                ExtensionType = 16
	ExtensionTypeKeyShare            ExtensionType = 40
	ExtensionTypePreSharedKey        ExtensionType = 41
	ExtensionTypeEarlyData           ExtensionType = 42
	ExtensionTypeSupportedVersions   ExtensionType = 43
	ExtensionTypeCookie              ExtensionType = 44
	ExtensionTypePSKKeyExchangeModes ExtensionType = 45
	ExtensionTypeTicketEarlyDataInfo ExtensionType = 46
)

// enum {...} NamedGroup
type NamedGroup uint16

const (
	// Elliptic Curve Groups.
	P256 NamedGroup = 23
	P384 NamedGroup = 24
	P521 NamedGroup = 25
	// ECDH functions.
	X25519 NamedGroup = 29
	X448   NamedGroup = 30
	// Finite field groups.
	FFDHE2048 NamedGroup = 256
	FFDHE3072 NamedGroup = 257
	FFDHE4096 NamedGroup = 258
	FFDHE6144 NamedGroup = 259
	FFDHE8192 NamedGroup = 260
)

// enum {...} PskKeyExchangeMode;
type PSKKeyExchangeMode uint8

const (
	PSKModeKE    PSKKeyExchangeMode = 0
	PSKModeDHEKE PSKKeyExchangeMode = 1
)

// enum {
//     update_not_requested(0), update_requested(1), (255)
// } KeyUpdateRequest;
type KeyUpdateRequest uint8

const (
	KeyUpdateNotRequested KeyUpdateRequest = 0
	KeyUpdateRequested    KeyUpdateRequest = 1
)

type State uint8

const (
	StateInit = 0

	// states valid for the client
	StateClientStart State = iota
	StateClientWaitSH
	StateClientWaitEE
	StateClientWaitCert
	StateClientWaitCV
	StateClientWaitFinished
	StateClientWaitCertCR
	StateClientConnected
	// states valid for the server
	StateServerStart State = iota
	StateServerRecvdCH
	StateServerNegotiated
	StateServerReadPastEarlyData
	StateServerWaitEOED
	StateServerWaitFlight2
	StateServerWaitCert
	StateServerWaitCV
	StateServerWaitFinished
	StateServerConnected
)

func (s State) String() string {
	switch s {
	case StateClientStart:
		return "Client START"
	case StateClientWaitSH:
		return "Client WAIT_SH"
	case StateClientWaitEE:
		return "Client WAIT_EE"
	case StateClientWaitCert:
		return "Client WAIT_CERT"
	case StateClientWaitCV:
		return "Client WAIT_CV"
	case StateClientWaitFinished:
		return "Client WAIT_FINISHED"
	case StateClientWaitCertCR:
		return "Client WAIT_CERT_CR"
	case StateClientConnected:
		return "Client CONNECTED"
	case StateServerStart:
		return "Server START"
	case StateServerRecvdCH:
		return "Server RECVD_CH"
	case StateServerNegotiated:
		return "Server NEGOTIATED"
	case StateServerReadPastEarlyData:
		return "Server READ_PAST_EARLY_DATA"
	case StateServerWaitEOED:
		return "Server WAIT_EOED"
	case StateServerWaitFlight2:
		return "Server WAIT_FLIGHT2"
	case StateServerWaitCert:
		return "Server WAIT_CERT"
	case StateServerWaitCV:
		return "Server WAIT_CV"
	case StateServerWaitFinished:
		return "Server WAIT_FINISHED"
	case StateServerConnected:
		return "Server CONNECTED"
	default:
		return fmt.Sprintf("unknown state: %d", s)
	}
}

// Epochs for DTLS (also used for key phase labelling)
type Epoch uint16

const (
	EpochClear           Epoch = 0
	EpochEarlyData       Epoch = 1
	EpochHandshakeData   Epoch = 2
	EpochApplicationData Epoch = 3
	EpochUpdate          Epoch = 4
)

func (e Epoch) label() string {
	switch e {
	case EpochClear:
		return "clear"
	case EpochEarlyData:
		return "early data"
	case EpochHandshakeData:
		return "handshake"
	case EpochApplicationData:
		return "application data"
	}
	return "Application data (updated)"
}

func assert(b bool) {
	if !b {
		panic("Assertion failed")
	}
}
