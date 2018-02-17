package mint

import (
	"fmt"
	"strconv"
)

var (
	supportedVersion uint16 = 0x7f15 // draft-21

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
