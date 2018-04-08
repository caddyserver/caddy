package mint

import (
	"bytes"
	"crypto"
	"crypto/aes"
	"crypto/cipher"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/hmac"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"fmt"
	"math/big"
	"time"

	"golang.org/x/crypto/curve25519"

	// Blank includes to ensure hash support
	_ "crypto/sha1"
	_ "crypto/sha256"
	_ "crypto/sha512"
)

var prng = rand.Reader

type aeadFactory func(key []byte) (cipher.AEAD, error)

type CipherSuiteParams struct {
	Suite  CipherSuite
	Cipher aeadFactory // Cipher factory
	Hash   crypto.Hash // Hash function
	KeyLen int         // Key length in octets
	IvLen  int         // IV length in octets
}

type signatureAlgorithm uint8

const (
	signatureAlgorithmUnknown = iota
	signatureAlgorithmRSA_PKCS1
	signatureAlgorithmRSA_PSS
	signatureAlgorithmECDSA
)

var (
	hashMap = map[SignatureScheme]crypto.Hash{
		RSA_PKCS1_SHA1:    crypto.SHA1,
		RSA_PKCS1_SHA256:  crypto.SHA256,
		RSA_PKCS1_SHA384:  crypto.SHA384,
		RSA_PKCS1_SHA512:  crypto.SHA512,
		ECDSA_P256_SHA256: crypto.SHA256,
		ECDSA_P384_SHA384: crypto.SHA384,
		ECDSA_P521_SHA512: crypto.SHA512,
		RSA_PSS_SHA256:    crypto.SHA256,
		RSA_PSS_SHA384:    crypto.SHA384,
		RSA_PSS_SHA512:    crypto.SHA512,
	}

	sigMap = map[SignatureScheme]signatureAlgorithm{
		RSA_PKCS1_SHA1:    signatureAlgorithmRSA_PKCS1,
		RSA_PKCS1_SHA256:  signatureAlgorithmRSA_PKCS1,
		RSA_PKCS1_SHA384:  signatureAlgorithmRSA_PKCS1,
		RSA_PKCS1_SHA512:  signatureAlgorithmRSA_PKCS1,
		ECDSA_P256_SHA256: signatureAlgorithmECDSA,
		ECDSA_P384_SHA384: signatureAlgorithmECDSA,
		ECDSA_P521_SHA512: signatureAlgorithmECDSA,
		RSA_PSS_SHA256:    signatureAlgorithmRSA_PSS,
		RSA_PSS_SHA384:    signatureAlgorithmRSA_PSS,
		RSA_PSS_SHA512:    signatureAlgorithmRSA_PSS,
	}

	curveMap = map[SignatureScheme]NamedGroup{
		ECDSA_P256_SHA256: P256,
		ECDSA_P384_SHA384: P384,
		ECDSA_P521_SHA512: P521,
	}

	newAESGCM = func(key []byte) (cipher.AEAD, error) {
		block, err := aes.NewCipher(key)
		if err != nil {
			return nil, err
		}

		// TLS always uses 12-byte nonces
		return cipher.NewGCMWithNonceSize(block, 12)
	}

	cipherSuiteMap = map[CipherSuite]CipherSuiteParams{
		TLS_AES_128_GCM_SHA256: {
			Suite:  TLS_AES_128_GCM_SHA256,
			Cipher: newAESGCM,
			Hash:   crypto.SHA256,
			KeyLen: 16,
			IvLen:  12,
		},
		TLS_AES_256_GCM_SHA384: {
			Suite:  TLS_AES_256_GCM_SHA384,
			Cipher: newAESGCM,
			Hash:   crypto.SHA384,
			KeyLen: 32,
			IvLen:  12,
		},
	}

	x509AlgMap = map[SignatureScheme]x509.SignatureAlgorithm{
		RSA_PKCS1_SHA1:    x509.SHA1WithRSA,
		RSA_PKCS1_SHA256:  x509.SHA256WithRSA,
		RSA_PKCS1_SHA384:  x509.SHA384WithRSA,
		RSA_PKCS1_SHA512:  x509.SHA512WithRSA,
		ECDSA_P256_SHA256: x509.ECDSAWithSHA256,
		ECDSA_P384_SHA384: x509.ECDSAWithSHA384,
		ECDSA_P521_SHA512: x509.ECDSAWithSHA512,
	}

	defaultRSAKeySize = 2048
)

func curveFromNamedGroup(group NamedGroup) (crv elliptic.Curve) {
	switch group {
	case P256:
		crv = elliptic.P256()
	case P384:
		crv = elliptic.P384()
	case P521:
		crv = elliptic.P521()
	}
	return
}

func namedGroupFromECDSAKey(key *ecdsa.PublicKey) (g NamedGroup) {
	switch key.Curve.Params().Name {
	case elliptic.P256().Params().Name:
		g = P256
	case elliptic.P384().Params().Name:
		g = P384
	case elliptic.P521().Params().Name:
		g = P521
	}
	return
}

func keyExchangeSizeFromNamedGroup(group NamedGroup) (size int) {
	size = 0
	switch group {
	case X25519:
		size = 32
	case P256:
		size = 65
	case P384:
		size = 97
	case P521:
		size = 133
	case FFDHE2048:
		size = 256
	case FFDHE3072:
		size = 384
	case FFDHE4096:
		size = 512
	case FFDHE6144:
		size = 768
	case FFDHE8192:
		size = 1024
	}
	return
}

func primeFromNamedGroup(group NamedGroup) (p *big.Int) {
	switch group {
	case FFDHE2048:
		p = finiteFieldPrime2048
	case FFDHE3072:
		p = finiteFieldPrime3072
	case FFDHE4096:
		p = finiteFieldPrime4096
	case FFDHE6144:
		p = finiteFieldPrime6144
	case FFDHE8192:
		p = finiteFieldPrime8192
	}
	return
}

func schemeValidForKey(alg SignatureScheme, key crypto.Signer) bool {
	sigType := sigMap[alg]
	switch key.(type) {
	case *rsa.PrivateKey:
		return sigType == signatureAlgorithmRSA_PKCS1 || sigType == signatureAlgorithmRSA_PSS
	case *ecdsa.PrivateKey:
		return sigType == signatureAlgorithmECDSA
	default:
		return false
	}
}

func ffdheKeyShareFromPrime(p *big.Int) (priv, pub *big.Int, err error) {
	primeLen := len(p.Bytes())
	for {
		// g = 2 for all ffdhe groups
		priv, err = rand.Int(prng, p)
		if err != nil {
			return
		}

		pub = big.NewInt(0)
		pub.Exp(big.NewInt(2), priv, p)

		if len(pub.Bytes()) == primeLen {
			return
		}
	}
}

func newKeyShare(group NamedGroup) (pub []byte, priv []byte, err error) {
	switch group {
	case P256, P384, P521:
		var x, y *big.Int
		crv := curveFromNamedGroup(group)
		priv, x, y, err = elliptic.GenerateKey(crv, prng)
		if err != nil {
			return
		}

		pub = elliptic.Marshal(crv, x, y)
		return

	case FFDHE2048, FFDHE3072, FFDHE4096, FFDHE6144, FFDHE8192:
		p := primeFromNamedGroup(group)
		x, X, err2 := ffdheKeyShareFromPrime(p)
		if err2 != nil {
			err = err2
			return
		}

		priv = x.Bytes()
		pubBytes := X.Bytes()

		numBytes := keyExchangeSizeFromNamedGroup(group)

		pub = make([]byte, numBytes)
		copy(pub[numBytes-len(pubBytes):], pubBytes)

		return

	case X25519:
		var private, public [32]byte
		_, err = prng.Read(private[:])
		if err != nil {
			return
		}

		curve25519.ScalarBaseMult(&public, &private)
		priv = private[:]
		pub = public[:]
		return

	default:
		return nil, nil, fmt.Errorf("tls.newkeyshare: Unsupported group %v", group)
	}
}

func keyAgreement(group NamedGroup, pub []byte, priv []byte) ([]byte, error) {
	switch group {
	case P256, P384, P521:
		if len(pub) != keyExchangeSizeFromNamedGroup(group) {
			return nil, fmt.Errorf("tls.keyagreement: Wrong public key size")
		}

		crv := curveFromNamedGroup(group)
		pubX, pubY := elliptic.Unmarshal(crv, pub)
		x, _ := crv.Params().ScalarMult(pubX, pubY, priv)
		xBytes := x.Bytes()

		numBytes := len(crv.Params().P.Bytes())

		ret := make([]byte, numBytes)
		copy(ret[numBytes-len(xBytes):], xBytes)

		return ret, nil

	case FFDHE2048, FFDHE3072, FFDHE4096, FFDHE6144, FFDHE8192:
		numBytes := keyExchangeSizeFromNamedGroup(group)
		if len(pub) != numBytes {
			return nil, fmt.Errorf("tls.keyagreement: Wrong public key size")
		}
		p := primeFromNamedGroup(group)
		x := big.NewInt(0).SetBytes(priv)
		Y := big.NewInt(0).SetBytes(pub)
		ZBytes := big.NewInt(0).Exp(Y, x, p).Bytes()

		ret := make([]byte, numBytes)
		copy(ret[numBytes-len(ZBytes):], ZBytes)

		return ret, nil

	case X25519:
		if len(pub) != keyExchangeSizeFromNamedGroup(group) {
			return nil, fmt.Errorf("tls.keyagreement: Wrong public key size")
		}

		var private, public, ret [32]byte
		copy(private[:], priv)
		copy(public[:], pub)
		curve25519.ScalarMult(&ret, &private, &public)

		return ret[:], nil

	default:
		return nil, fmt.Errorf("tls.keyagreement: Unsupported group %v", group)
	}
}

func newSigningKey(sig SignatureScheme) (crypto.Signer, error) {
	switch sig {
	case RSA_PKCS1_SHA1, RSA_PKCS1_SHA256,
		RSA_PKCS1_SHA384, RSA_PKCS1_SHA512,
		RSA_PSS_SHA256, RSA_PSS_SHA384,
		RSA_PSS_SHA512:
		return rsa.GenerateKey(prng, defaultRSAKeySize)
	case ECDSA_P256_SHA256:
		return ecdsa.GenerateKey(elliptic.P256(), prng)
	case ECDSA_P384_SHA384:
		return ecdsa.GenerateKey(elliptic.P384(), prng)
	case ECDSA_P521_SHA512:
		return ecdsa.GenerateKey(elliptic.P521(), prng)
	default:
		return nil, fmt.Errorf("tls.newsigningkey: Unsupported signature algorithm [%04x]", sig)
	}
}

// XXX(rlb): Copied from crypto/x509
type ecdsaSignature struct {
	R, S *big.Int
}

func sign(alg SignatureScheme, privateKey crypto.Signer, sigInput []byte) ([]byte, error) {
	var opts crypto.SignerOpts

	hash := hashMap[alg]
	if hash == crypto.SHA1 {
		return nil, fmt.Errorf("tls.crypt.sign: Use of SHA-1 is forbidden")
	}

	sigType := sigMap[alg]
	var realInput []byte
	switch key := privateKey.(type) {
	case *rsa.PrivateKey:
		switch {
		case allowPKCS1 && sigType == signatureAlgorithmRSA_PKCS1:
			logf(logTypeCrypto, "signing with PKCS1, hashSize=[%d]", hash.Size())
			opts = hash
		case !allowPKCS1 && sigType == signatureAlgorithmRSA_PKCS1:
			fallthrough
		case sigType == signatureAlgorithmRSA_PSS:
			logf(logTypeCrypto, "signing with PSS, hashSize=[%d]", hash.Size())
			opts = &rsa.PSSOptions{SaltLength: hash.Size(), Hash: hash}
		default:
			return nil, fmt.Errorf("tls.crypto.sign: Unsupported algorithm for RSA key")
		}

		h := hash.New()
		h.Write(sigInput)
		realInput = h.Sum(nil)
	case *ecdsa.PrivateKey:
		if sigType != signatureAlgorithmECDSA {
			return nil, fmt.Errorf("tls.crypto.sign: Unsupported algorithm for ECDSA key")
		}

		algGroup := curveMap[alg]
		keyGroup := namedGroupFromECDSAKey(key.Public().(*ecdsa.PublicKey))
		if algGroup != keyGroup {
			return nil, fmt.Errorf("tls.crypto.sign: Unsupported hash/curve combination")
		}

		h := hash.New()
		h.Write(sigInput)
		realInput = h.Sum(nil)
	default:
		return nil, fmt.Errorf("tls.crypto.sign: Unsupported private key type")
	}

	sig, err := privateKey.Sign(prng, realInput, opts)
	logf(logTypeCrypto, "signature: %x", sig)
	return sig, err
}

func verify(alg SignatureScheme, publicKey crypto.PublicKey, sigInput []byte, sig []byte) error {
	hash := hashMap[alg]

	if hash == crypto.SHA1 {
		return fmt.Errorf("tls.crypt.sign: Use of SHA-1 is forbidden")
	}

	sigType := sigMap[alg]
	switch pub := publicKey.(type) {
	case *rsa.PublicKey:
		switch {
		case allowPKCS1 && sigType == signatureAlgorithmRSA_PKCS1:
			logf(logTypeCrypto, "verifying with PKCS1, hashSize=[%d]", hash.Size())

			h := hash.New()
			h.Write(sigInput)
			realInput := h.Sum(nil)
			return rsa.VerifyPKCS1v15(pub, hash, realInput, sig)
		case !allowPKCS1 && sigType == signatureAlgorithmRSA_PKCS1:
			fallthrough
		case sigType == signatureAlgorithmRSA_PSS:
			logf(logTypeCrypto, "verifying with PSS, hashSize=[%d]", hash.Size())
			opts := &rsa.PSSOptions{SaltLength: hash.Size(), Hash: hash}

			h := hash.New()
			h.Write(sigInput)
			realInput := h.Sum(nil)
			return rsa.VerifyPSS(pub, hash, realInput, sig, opts)
		default:
			return fmt.Errorf("tls.verify: Unsupported algorithm for RSA key")
		}

	case *ecdsa.PublicKey:
		if sigType != signatureAlgorithmECDSA {
			return fmt.Errorf("tls.verify: Unsupported algorithm for ECDSA key")
		}

		if curveMap[alg] != namedGroupFromECDSAKey(pub) {
			return fmt.Errorf("tls.verify: Unsupported curve for ECDSA key")
		}

		ecdsaSig := new(ecdsaSignature)
		if rest, err := asn1.Unmarshal(sig, ecdsaSig); err != nil {
			return err
		} else if len(rest) != 0 {
			return fmt.Errorf("tls.verify: trailing data after ECDSA signature")
		}
		if ecdsaSig.R.Sign() <= 0 || ecdsaSig.S.Sign() <= 0 {
			return fmt.Errorf("tls.verify: ECDSA signature contained zero or negative values")
		}

		h := hash.New()
		h.Write(sigInput)
		realInput := h.Sum(nil)
		if !ecdsa.Verify(pub, realInput, ecdsaSig.R, ecdsaSig.S) {
			return fmt.Errorf("tls.verify: ECDSA verification failure")
		}
		return nil
	default:
		return fmt.Errorf("tls.verify: Unsupported key type")
	}
}

//                  0
//                  |
//                  v
//    PSK ->  HKDF-Extract = Early Secret
//                  |
//                  +-----> Derive-Secret(.,
//                  |                     "ext binder" |
//                  |                     "res binder",
//                  |                     "")
//                  |                     = binder_key
//                  |
//                  +-----> Derive-Secret(., "c e traffic",
//                  |                     ClientHello)
//                  |                     = client_early_traffic_secret
//                  |
//                  +-----> Derive-Secret(., "e exp master",
//                  |                     ClientHello)
//                  |                     = early_exporter_master_secret
//                  v
//            Derive-Secret(., "derived", "")
//                  |
//                  v
// (EC)DHE -> HKDF-Extract = Handshake Secret
//                  |
//                  +-----> Derive-Secret(., "c hs traffic",
//                  |                     ClientHello...ServerHello)
//                  |                     = client_handshake_traffic_secret
//                  |
//                  +-----> Derive-Secret(., "s hs traffic",
//                  |                     ClientHello...ServerHello)
//                  |                     = server_handshake_traffic_secret
//                  v
//            Derive-Secret(., "derived", "")
//                  |
//                  v
//       0 -> HKDF-Extract = Master Secret
//                  |
//                  +-----> Derive-Secret(., "c ap traffic",
//                  |                     ClientHello...server Finished)
//                  |                     = client_application_traffic_secret_0
//                  |
//                  +-----> Derive-Secret(., "s ap traffic",
//                  |                     ClientHello...server Finished)
//                  |                     = server_application_traffic_secret_0
//                  |
//                  +-----> Derive-Secret(., "exp master",
//                  |                     ClientHello...server Finished)
//                  |                     = exporter_master_secret
//                  |
//                  +-----> Derive-Secret(., "res master",
//                                        ClientHello...client Finished)
//                                        = resumption_master_secret

// From RFC 5869
// PRK = HMAC-Hash(salt, IKM)
func HkdfExtract(hash crypto.Hash, saltIn, input []byte) []byte {
	salt := saltIn

	// if [salt is] not provided, it is set to a string of HashLen zeros
	if salt == nil {
		salt = bytes.Repeat([]byte{0}, hash.Size())
	}

	h := hmac.New(hash.New, salt)
	h.Write(input)
	out := h.Sum(nil)

	logf(logTypeCrypto, "HKDF Extract:\n")
	logf(logTypeCrypto, "Salt [%d]: %x\n", len(salt), salt)
	logf(logTypeCrypto, "Input [%d]: %x\n", len(input), input)
	logf(logTypeCrypto, "Output [%d]: %x\n", len(out), out)

	return out
}

const (
	labelExternalBinder                 = "ext binder"
	labelResumptionBinder               = "res binder"
	labelEarlyTrafficSecret             = "c e traffic"
	labelEarlyExporterSecret            = "e exp master"
	labelClientHandshakeTrafficSecret   = "c hs traffic"
	labelServerHandshakeTrafficSecret   = "s hs traffic"
	labelClientApplicationTrafficSecret = "c ap traffic"
	labelServerApplicationTrafficSecret = "s ap traffic"
	labelExporterSecret                 = "exp master"
	labelResumptionSecret               = "res master"
	labelDerived                        = "derived"
	labelFinished                       = "finished"
	labelResumption                     = "resumption"
)

// struct HkdfLabel {
//    uint16 length;
//    opaque label<9..255>;
//    opaque hash_value<0..255>;
// };
func hkdfEncodeLabel(labelIn string, hashValue []byte, outLen int) []byte {
	label := "tls13 " + labelIn

	labelLen := len(label)
	hashLen := len(hashValue)
	hkdfLabel := make([]byte, 2+1+labelLen+1+hashLen)
	hkdfLabel[0] = byte(outLen >> 8)
	hkdfLabel[1] = byte(outLen)
	hkdfLabel[2] = byte(labelLen)
	copy(hkdfLabel[3:3+labelLen], []byte(label))
	hkdfLabel[3+labelLen] = byte(hashLen)
	copy(hkdfLabel[3+labelLen+1:], hashValue)

	return hkdfLabel
}

func HkdfExpand(hash crypto.Hash, prk, info []byte, outLen int) []byte {
	out := []byte{}
	T := []byte{}
	i := byte(1)
	for len(out) < outLen {
		block := append(T, info...)
		block = append(block, i)

		h := hmac.New(hash.New, prk)
		h.Write(block)

		T = h.Sum(nil)
		out = append(out, T...)
		i++
	}
	return out[:outLen]
}

func HkdfExpandLabel(hash crypto.Hash, secret []byte, label string, hashValue []byte, outLen int) []byte {
	info := hkdfEncodeLabel(label, hashValue, outLen)
	derived := HkdfExpand(hash, secret, info, outLen)

	logf(logTypeCrypto, "HKDF Expand: label=[tls13 ] + '%s',requested length=%d\n", label, outLen)
	logf(logTypeCrypto, "PRK [%d]: %x\n", len(secret), secret)
	logf(logTypeCrypto, "Hash [%d]: %x\n", len(hashValue), hashValue)
	logf(logTypeCrypto, "Info [%d]: %x\n", len(info), info)
	logf(logTypeCrypto, "Derived key [%d]: %x\n", len(derived), derived)

	return derived
}

func deriveSecret(params CipherSuiteParams, secret []byte, label string, messageHash []byte) []byte {
	return HkdfExpandLabel(params.Hash, secret, label, messageHash, params.Hash.Size())
}

func computeFinishedData(params CipherSuiteParams, baseKey []byte, input []byte) []byte {
	macKey := HkdfExpandLabel(params.Hash, baseKey, labelFinished, []byte{}, params.Hash.Size())
	mac := hmac.New(params.Hash.New, macKey)
	mac.Write(input)
	return mac.Sum(nil)
}

type keySet struct {
	cipher aeadFactory
	key    []byte
	iv     []byte
}

func makeTrafficKeys(params CipherSuiteParams, secret []byte) keySet {
	logf(logTypeCrypto, "making traffic keys: secret=%x", secret)
	return keySet{
		cipher: params.Cipher,
		key:    HkdfExpandLabel(params.Hash, secret, "key", []byte{}, params.KeyLen),
		iv:     HkdfExpandLabel(params.Hash, secret, "iv", []byte{}, params.IvLen),
	}
}

func MakeNewSelfSignedCert(name string, alg SignatureScheme) (crypto.Signer, *x509.Certificate, error) {
	priv, err := newSigningKey(alg)
	if err != nil {
		return nil, nil, err
	}

	cert, err := newSelfSigned(name, alg, priv)
	if err != nil {
		return nil, nil, err
	}
	return priv, cert, nil
}

func newSelfSigned(name string, alg SignatureScheme, priv crypto.Signer) (*x509.Certificate, error) {
	sigAlg, ok := x509AlgMap[alg]
	if !ok {
		return nil, fmt.Errorf("tls.selfsigned: Unknown signature algorithm [%04x]", alg)
	}
	if len(name) == 0 {
		return nil, fmt.Errorf("tls.selfsigned: No name provided")
	}

	serial, err := rand.Int(rand.Reader, big.NewInt(0xA0A0A0A0))
	if err != nil {
		return nil, err
	}

	template := &x509.Certificate{
		SerialNumber:       serial,
		NotBefore:          time.Now(),
		NotAfter:           time.Now().AddDate(0, 0, 1),
		SignatureAlgorithm: sigAlg,
		Subject:            pkix.Name{CommonName: name},
		DNSNames:           []string{name},
		KeyUsage:           x509.KeyUsageDigitalSignature | x509.KeyUsageKeyAgreement | x509.KeyUsageKeyEncipherment,
		ExtKeyUsage:        []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}
	der, err := x509.CreateCertificate(prng, template, template, priv.Public(), priv)
	if err != nil {
		return nil, err
	}

	// It is safe to ignore the error here because we're parsing known-good data
	cert, _ := x509.ParseCertificate(der)
	return cert, nil
}
