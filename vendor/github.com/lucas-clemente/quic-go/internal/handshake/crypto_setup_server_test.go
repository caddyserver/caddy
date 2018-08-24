package handshake

import (
	"bytes"
	"encoding/binary"
	"errors"
	"io"
	"net"
	"time"

	"github.com/lucas-clemente/quic-go/internal/crypto"
	"github.com/lucas-clemente/quic-go/internal/mocks/crypto"
	"github.com/lucas-clemente/quic-go/internal/protocol"
	"github.com/lucas-clemente/quic-go/internal/utils"
	"github.com/lucas-clemente/quic-go/qerr"

	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"
)

type mockKEX struct {
	ephermal       bool
	sharedKeyError error
}

func (m *mockKEX) PublicKey() []byte {
	if m.ephermal {
		return []byte("ephermal pub")
	}
	return []byte("initial public")
}

func (m *mockKEX) CalculateSharedKey(otherPublic []byte) ([]byte, error) {
	if m.sharedKeyError != nil {
		return nil, m.sharedKeyError
	}
	if m.ephermal {
		return []byte("shared ephermal"), nil
	}
	return []byte("shared key"), nil
}

type mockSigner struct {
	gotCHLO bool
}

func (s *mockSigner) SignServerProof(sni string, chlo []byte, serverConfigData []byte) ([]byte, error) {
	if len(chlo) > 0 {
		s.gotCHLO = true
	}
	return []byte("proof"), nil
}
func (*mockSigner) GetCertsCompressed(sni string, common, cached []byte) ([]byte, error) {
	return []byte("certcompressed"), nil
}
func (*mockSigner) GetLeafCert(sni string) ([]byte, error) {
	return []byte("certuncompressed"), nil
}

func mockQuicCryptoKeyDerivation(forwardSecure bool, sharedSecret, nonces []byte, connID protocol.ConnectionID, chlo []byte, scfg []byte, cert []byte, divNonce []byte, pers protocol.Perspective) (crypto.AEAD, error) {
	return mockcrypto.NewMockAEAD(mockCtrl), nil
}

type mockStream struct {
	unblockRead chan struct{}
	dataToRead  bytes.Buffer
	dataWritten bytes.Buffer
}

var _ io.ReadWriter = &mockStream{}

var errMockStreamClosing = errors.New("mock stream closing")

func newMockStream() *mockStream {
	return &mockStream{unblockRead: make(chan struct{})}
}

// call Close to make Read return
func (s *mockStream) Read(p []byte) (int, error) {
	n, _ := s.dataToRead.Read(p)
	if n == 0 { // block if there's no data
		<-s.unblockRead
		return 0, errMockStreamClosing
	}
	return n, nil // never return an EOF
}

func (s *mockStream) Write(p []byte) (int, error) {
	return s.dataWritten.Write(p)
}

func (s *mockStream) close() {
	close(s.unblockRead)
}

type mockCookieProtector struct {
	decodeErr error
}

var _ cookieProtector = &mockCookieProtector{}

func (mockCookieProtector) NewToken(sourceAddr []byte) ([]byte, error) {
	return append([]byte("token "), sourceAddr...), nil
}

func (s mockCookieProtector) DecodeToken(data []byte) ([]byte, error) {
	if s.decodeErr != nil {
		return nil, s.decodeErr
	}
	if len(data) < 6 {
		return nil, errors.New("token too short")
	}
	return data[6:], nil
}

var _ = Describe("Server Crypto Setup", func() {
	var (
		kex               *mockKEX
		signer            *mockSigner
		scfg              *ServerConfig
		cs                *cryptoSetupServer
		stream            *mockStream
		paramsChan        chan TransportParameters
		handshakeEvent    chan struct{}
		nonce32           []byte
		versionTag        []byte
		validSTK          []byte
		aead              []byte
		kexs              []byte
		version           protocol.VersionNumber
		supportedVersions []protocol.VersionNumber
		sourceAddrValid   bool
	)

	const (
		expectedInitialNonceLen = 32
		expectedFSNonceLen      = 64
	)

	BeforeEach(func() {
		var err error
		remoteAddr := &net.UDPAddr{IP: net.IPv4(1, 2, 3, 4), Port: 1234}

		// use a buffered channel here, so that we can parse a CHLO without having to receive the TransportParameters to avoid blocking
		paramsChan = make(chan TransportParameters, 1)
		handshakeEvent = make(chan struct{}, 2)
		stream = newMockStream()
		kex = &mockKEX{}
		signer = &mockSigner{}
		scfg, err = NewServerConfig(kex, signer)
		nonce32 = make([]byte, 32)
		aead = []byte("AESG")
		kexs = []byte("C255")
		copy(nonce32[4:12], scfg.obit) // set the OBIT value at the right position
		versionTag = make([]byte, 4)
		binary.BigEndian.PutUint32(versionTag, uint32(protocol.VersionWhatever))
		Expect(err).NotTo(HaveOccurred())
		version = protocol.SupportedVersions[len(protocol.SupportedVersions)-1]
		supportedVersions = []protocol.VersionNumber{version, 98, 99}
		csInt, err := NewCryptoSetup(
			stream,
			protocol.ConnectionID{1, 2, 3, 4, 5, 6, 7, 8},
			remoteAddr,
			version,
			make([]byte, 32), // div nonce
			scfg,
			&TransportParameters{IdleTimeout: protocol.DefaultIdleTimeout},
			supportedVersions,
			nil,
			paramsChan,
			handshakeEvent,
			utils.DefaultLogger,
		)
		Expect(err).NotTo(HaveOccurred())
		cs = csInt.(*cryptoSetupServer)
		cs.scfg.cookieGenerator.cookieProtector = &mockCookieProtector{}
		validSTK, err = cs.scfg.cookieGenerator.NewToken(remoteAddr)
		Expect(err).NotTo(HaveOccurred())
		sourceAddrValid = true
		cs.acceptSTKCallback = func(_ net.Addr, _ *Cookie) bool { return sourceAddrValid }
		cs.keyDerivation = mockQuicCryptoKeyDerivation
		cs.keyExchange = func() (crypto.KeyExchange, error) { return &mockKEX{ephermal: true}, nil }
		cs.nullAEAD = mockcrypto.NewMockAEAD(mockCtrl)
		cs.cryptoStream = stream
	})

	Context("when responding to client messages", func() {
		var cert []byte
		var xlct []byte
		var fullCHLO map[Tag][]byte

		BeforeEach(func() {
			xlct = make([]byte, 8)
			var err error
			cert, err = cs.scfg.certChain.GetLeafCert("")
			Expect(err).ToNot(HaveOccurred())
			binary.LittleEndian.PutUint64(xlct, crypto.HashCert(cert))
			fullCHLO = map[Tag][]byte{
				TagSCID: scfg.ID,
				TagSNI:  []byte("quic.clemente.io"),
				TagNONC: nonce32,
				TagSTK:  validSTK,
				TagXLCT: xlct,
				TagAEAD: aead,
				TagKEXS: kexs,
				TagPUBS: bytes.Repeat([]byte{'e'}, 31),
				TagVER:  versionTag,
			}
		})

		It("doesn't support Chrome's no STOP_WAITING experiment", func() {
			HandshakeMessage{
				Tag: TagCHLO,
				Data: map[Tag][]byte{
					TagNSTP: []byte("foobar"),
				},
			}.Write(&stream.dataToRead)
			err := cs.HandleCryptoStream()
			Expect(err).To(MatchError(ErrNSTPExperiment))
		})

		It("reads the transport parameters sent by the client", func() {
			sourceAddrValid = true
			fullCHLO[TagICSL] = []byte{0x37, 0x13, 0, 0}
			_, err := cs.handleMessage(bytes.Repeat([]byte{'a'}, protocol.MinClientHelloSize), fullCHLO)
			Expect(err).ToNot(HaveOccurred())
			var params TransportParameters
			Expect(paramsChan).To(Receive(&params))
			Expect(params.IdleTimeout).To(Equal(0x1337 * time.Second))
		})

		It("generates REJ messages", func() {
			sourceAddrValid = false
			response, err := cs.handleInchoateCHLO("", bytes.Repeat([]byte{'a'}, protocol.MinClientHelloSize), nil)
			Expect(err).ToNot(HaveOccurred())
			Expect(response).To(HavePrefix("REJ"))
			Expect(response).To(ContainSubstring("initial public"))
			Expect(response).ToNot(ContainSubstring("certcompressed"))
			Expect(response).ToNot(ContainSubstring("proof"))
			Expect(signer.gotCHLO).To(BeFalse())
		})

		It("REJ messages don't include cert or proof without STK", func() {
			sourceAddrValid = false
			response, err := cs.handleInchoateCHLO("", bytes.Repeat([]byte{'a'}, protocol.MinClientHelloSize), nil)
			Expect(err).ToNot(HaveOccurred())
			Expect(response).To(HavePrefix("REJ"))
			Expect(response).ToNot(ContainSubstring("certcompressed"))
			Expect(response).ToNot(ContainSubstring("proof"))
			Expect(signer.gotCHLO).To(BeFalse())
		})

		It("REJ messages include cert and proof with valid STK", func() {
			sourceAddrValid = true
			response, err := cs.handleInchoateCHLO("", bytes.Repeat([]byte{'a'}, protocol.MinClientHelloSize), map[Tag][]byte{
				TagSTK: validSTK,
				TagSNI: []byte("foo"),
			})
			Expect(err).ToNot(HaveOccurred())
			Expect(response).To(HavePrefix("REJ"))
			Expect(response).To(ContainSubstring("certcompressed"))
			Expect(response).To(ContainSubstring("proof"))
			Expect(signer.gotCHLO).To(BeTrue())
		})

		It("generates SHLO messages", func() {
			var checkedSecure, checkedForwardSecure bool
			cs.keyDerivation = func(forwardSecure bool, sharedSecret, nonces []byte, connID protocol.ConnectionID, chlo []byte, scfg []byte, cert []byte, divNonce []byte, pers protocol.Perspective) (crypto.AEAD, error) {
				if forwardSecure {
					Expect(nonces).To(HaveLen(expectedFSNonceLen))
					checkedForwardSecure = true
					Expect(sharedSecret).To(Equal([]byte("shared ephermal")))
				} else {
					Expect(nonces).To(HaveLen(expectedInitialNonceLen))
					Expect(sharedSecret).To(Equal([]byte("shared key")))
					checkedSecure = true
				}
				return mockcrypto.NewMockAEAD(mockCtrl), nil
			}

			response, err := cs.handleCHLO("", []byte("chlo-data"), map[Tag][]byte{
				TagPUBS: []byte("pubs-c"),
				TagNONC: nonce32,
				TagAEAD: aead,
				TagKEXS: kexs,
			})
			Expect(err).ToNot(HaveOccurred())
			Expect(response).To(HavePrefix("SHLO"))
			message, err := ParseHandshakeMessage(bytes.NewReader(response))
			Expect(err).ToNot(HaveOccurred())
			Expect(message.Data).To(HaveKeyWithValue(TagPUBS, []byte("ephermal pub")))
			Expect(message.Data).To(HaveKey(TagSNO))
			Expect(message.Data).To(HaveKey(TagVER))
			Expect(message.Data[TagVER]).To(HaveLen(4 * len(supportedVersions)))
			for _, v := range supportedVersions {
				b := &bytes.Buffer{}
				utils.BigEndian.WriteUint32(b, uint32(v))
				Expect(message.Data[TagVER]).To(ContainSubstring(b.String()))
			}
			Expect(checkedSecure).To(BeTrue())
			Expect(checkedForwardSecure).To(BeTrue())
		})

		It("handles long handshake", func() {
			HandshakeMessage{
				Tag: TagCHLO,
				Data: map[Tag][]byte{
					TagSNI: []byte("quic.clemente.io"),
					TagSTK: validSTK,
					TagPAD: bytes.Repeat([]byte{'a'}, protocol.MinClientHelloSize),
					TagVER: versionTag,
				},
			}.Write(&stream.dataToRead)
			HandshakeMessage{Tag: TagCHLO, Data: fullCHLO}.Write(&stream.dataToRead)
			err := cs.HandleCryptoStream()
			Expect(err).NotTo(HaveOccurred())
			Expect(stream.dataWritten.Bytes()).To(HavePrefix("REJ"))
			Expect(handshakeEvent).To(Receive()) // for the switch to secure
			Expect(stream.dataWritten.Bytes()).To(ContainSubstring("SHLO"))
			Expect(handshakeEvent).To(Receive()) // for the switch to forward secure
			Expect(handshakeEvent).ToNot(BeClosed())
		})

		It("rejects client nonces that have the wrong length", func() {
			fullCHLO[TagNONC] = []byte("too short client nonce")
			HandshakeMessage{Tag: TagCHLO, Data: fullCHLO}.Write(&stream.dataToRead)
			err := cs.HandleCryptoStream()
			Expect(err).To(MatchError(qerr.Error(qerr.InvalidCryptoMessageParameter, "invalid client nonce length")))
		})

		It("rejects client nonces that have the wrong OBIT value", func() {
			fullCHLO[TagNONC] = make([]byte, 32) // the OBIT value is nonce[4:12] and here just initialized to 0
			HandshakeMessage{Tag: TagCHLO, Data: fullCHLO}.Write(&stream.dataToRead)
			err := cs.HandleCryptoStream()
			Expect(err).To(MatchError(qerr.Error(qerr.InvalidCryptoMessageParameter, "OBIT not matching")))
		})

		It("errors if it can't calculate a shared key", func() {
			testErr := errors.New("test error")
			kex.sharedKeyError = testErr
			HandshakeMessage{Tag: TagCHLO, Data: fullCHLO}.Write(&stream.dataToRead)
			err := cs.HandleCryptoStream()
			Expect(err).To(MatchError(testErr))
		})

		It("handles 0-RTT handshake", func() {
			HandshakeMessage{Tag: TagCHLO, Data: fullCHLO}.Write(&stream.dataToRead)
			err := cs.HandleCryptoStream()
			Expect(err).NotTo(HaveOccurred())
			Expect(stream.dataWritten.Bytes()).To(HavePrefix("SHLO"))
			Expect(stream.dataWritten.Bytes()).ToNot(ContainSubstring("REJ"))
			Expect(handshakeEvent).To(Receive()) // for the switch to secure
			Expect(handshakeEvent).To(Receive()) // for the switch to forward secure
			Expect(handshakeEvent).ToNot(BeClosed())
		})

		It("recognizes inchoate CHLOs missing SCID", func() {
			delete(fullCHLO, TagSCID)
			Expect(cs.isInchoateCHLO(fullCHLO, cert)).To(BeTrue())
		})

		It("recognizes inchoate CHLOs missing PUBS", func() {
			delete(fullCHLO, TagPUBS)
			Expect(cs.isInchoateCHLO(fullCHLO, cert)).To(BeTrue())
		})

		It("recognizes inchoate CHLOs with missing XLCT", func() {
			delete(fullCHLO, TagXLCT)
			Expect(cs.isInchoateCHLO(fullCHLO, cert)).To(BeTrue())
		})

		It("recognizes inchoate CHLOs with wrong length XLCT", func() {
			fullCHLO[TagXLCT] = bytes.Repeat([]byte{'f'}, 7) // should be 8 bytes
			Expect(cs.isInchoateCHLO(fullCHLO, cert)).To(BeTrue())
		})

		It("recognizes inchoate CHLOs with wrong XLCT", func() {
			fullCHLO[TagXLCT] = bytes.Repeat([]byte{'f'}, 8)
			Expect(cs.isInchoateCHLO(fullCHLO, cert)).To(BeTrue())
		})

		It("recognizes inchoate CHLOs with an invalid STK", func() {
			testErr := errors.New("STK invalid")
			cs.scfg.cookieGenerator.cookieProtector.(*mockCookieProtector).decodeErr = testErr
			Expect(cs.isInchoateCHLO(fullCHLO, cert)).To(BeTrue())
		})

		It("recognizes proper CHLOs", func() {
			Expect(cs.isInchoateCHLO(fullCHLO, cert)).To(BeFalse())
		})

		It("rejects CHLOs without the version tag", func() {
			HandshakeMessage{
				Tag: TagCHLO,
				Data: map[Tag][]byte{
					TagSCID: scfg.ID,
					TagSNI:  []byte("quic.clemente.io"),
				},
			}.Write(&stream.dataToRead)
			err := cs.HandleCryptoStream()
			Expect(err).To(MatchError(qerr.Error(qerr.InvalidCryptoMessageParameter, "client hello missing version tag")))
		})

		It("rejects CHLOs with a version tag that has the wrong length", func() {
			fullCHLO[TagVER] = []byte{0x13, 0x37} // should be 4 bytes
			HandshakeMessage{Tag: TagCHLO, Data: fullCHLO}.Write(&stream.dataToRead)
			err := cs.HandleCryptoStream()
			Expect(err).To(MatchError(qerr.Error(qerr.InvalidCryptoMessageParameter, "incorrect version tag")))
		})

		It("detects version downgrade attacks", func() {
			highestSupportedVersion := supportedVersions[len(supportedVersions)-1]
			lowestSupportedVersion := supportedVersions[0]
			Expect(highestSupportedVersion).ToNot(Equal(lowestSupportedVersion))
			cs.version = highestSupportedVersion
			b := make([]byte, 4)
			binary.BigEndian.PutUint32(b, uint32(lowestSupportedVersion))
			fullCHLO[TagVER] = b
			HandshakeMessage{Tag: TagCHLO, Data: fullCHLO}.Write(&stream.dataToRead)
			err := cs.HandleCryptoStream()
			Expect(err).To(MatchError(qerr.Error(qerr.VersionNegotiationMismatch, "Downgrade attack detected")))
		})

		It("accepts a non-matching version tag in the CHLO, if it is an unsupported version", func() {
			supportedVersion := protocol.SupportedVersions[0]
			unsupportedVersion := supportedVersion + 1000
			Expect(protocol.IsSupportedVersion(supportedVersions, unsupportedVersion)).To(BeFalse())
			cs.version = supportedVersion
			b := make([]byte, 4)
			binary.BigEndian.PutUint32(b, uint32(unsupportedVersion))
			fullCHLO[TagVER] = b
			HandshakeMessage{Tag: TagCHLO, Data: fullCHLO}.Write(&stream.dataToRead)
			err := cs.HandleCryptoStream()
			Expect(err).ToNot(HaveOccurred())
		})

		It("errors if the AEAD tag is missing", func() {
			delete(fullCHLO, TagAEAD)
			HandshakeMessage{Tag: TagCHLO, Data: fullCHLO}.Write(&stream.dataToRead)
			err := cs.HandleCryptoStream()
			Expect(err).To(MatchError(qerr.Error(qerr.CryptoNoSupport, "Unsupported AEAD or KEXS")))
		})

		It("errors if the AEAD tag has the wrong value", func() {
			fullCHLO[TagAEAD] = []byte("wrong")
			HandshakeMessage{Tag: TagCHLO, Data: fullCHLO}.Write(&stream.dataToRead)
			err := cs.HandleCryptoStream()
			Expect(err).To(MatchError(qerr.Error(qerr.CryptoNoSupport, "Unsupported AEAD or KEXS")))
		})

		It("errors if the KEXS tag is missing", func() {
			delete(fullCHLO, TagKEXS)
			HandshakeMessage{Tag: TagCHLO, Data: fullCHLO}.Write(&stream.dataToRead)
			err := cs.HandleCryptoStream()
			Expect(err).To(MatchError(qerr.Error(qerr.CryptoNoSupport, "Unsupported AEAD or KEXS")))
		})

		It("errors if the KEXS tag has the wrong value", func() {
			fullCHLO[TagKEXS] = []byte("wrong")
			HandshakeMessage{Tag: TagCHLO, Data: fullCHLO}.Write(&stream.dataToRead)
			err := cs.HandleCryptoStream()
			Expect(err).To(MatchError(qerr.Error(qerr.CryptoNoSupport, "Unsupported AEAD or KEXS")))
		})
	})

	It("errors without SNI", func() {
		HandshakeMessage{
			Tag: TagCHLO,
			Data: map[Tag][]byte{
				TagSTK: validSTK,
			},
		}.Write(&stream.dataToRead)
		err := cs.HandleCryptoStream()
		Expect(err).To(MatchError("CryptoMessageParameterNotFound: SNI required"))
	})

	It("errors with empty SNI", func() {
		HandshakeMessage{
			Tag: TagCHLO,
			Data: map[Tag][]byte{
				TagSTK: validSTK,
				TagSNI: nil,
			},
		}.Write(&stream.dataToRead)
		err := cs.HandleCryptoStream()
		Expect(err).To(MatchError("CryptoMessageParameterNotFound: SNI required"))
	})

	It("errors with invalid message", func() {
		stream.dataToRead.Write([]byte("invalid message"))
		err := cs.HandleCryptoStream()
		Expect(err).To(MatchError(qerr.HandshakeFailed))
	})

	It("errors with non-CHLO message", func() {
		HandshakeMessage{Tag: TagPAD, Data: nil}.Write(&stream.dataToRead)
		err := cs.HandleCryptoStream()
		Expect(err).To(MatchError(qerr.InvalidCryptoMessageType))
	})

	Context("escalating crypto", func() {
		doCHLO := func() {
			_, err := cs.handleCHLO("", []byte("chlo-data"), map[Tag][]byte{
				TagPUBS: []byte("pubs-c"),
				TagNONC: nonce32,
				TagAEAD: aead,
				TagKEXS: kexs,
			})
			Expect(err).ToNot(HaveOccurred())
			Expect(handshakeEvent).To(Receive()) // for the switch to secure
			close(cs.sentSHLO)
		}

		Context("null encryption", func() {
			It("is used initially", func() {
				cs.nullAEAD.(*mockcrypto.MockAEAD).EXPECT().Seal(nil, []byte("foobar"), protocol.PacketNumber(10), []byte{}).Return([]byte("foobar signed"))
				enc, sealer := cs.GetSealer()
				Expect(enc).To(Equal(protocol.EncryptionUnencrypted))
				d := sealer.Seal(nil, []byte("foobar"), 10, []byte{})
				Expect(d).To(Equal([]byte("foobar signed")))
			})

			It("is used for the crypto stream", func() {
				cs.nullAEAD.(*mockcrypto.MockAEAD).EXPECT().Seal(nil, []byte("foobar"), protocol.PacketNumber(0), []byte{})
				enc, sealer := cs.GetSealerForCryptoStream()
				Expect(enc).To(Equal(protocol.EncryptionUnencrypted))
				sealer.Seal(nil, []byte("foobar"), 0, []byte{})
			})

			It("is accepted initially", func() {
				cs.nullAEAD.(*mockcrypto.MockAEAD).EXPECT().Open(nil, []byte("unencrypted"), protocol.PacketNumber(5), []byte{}).Return([]byte("decrypted"), nil)
				d, enc, err := cs.Open(nil, []byte("unencrypted"), 5, []byte{})
				Expect(err).ToNot(HaveOccurred())
				Expect(d).To(Equal([]byte("decrypted")))
				Expect(enc).To(Equal(protocol.EncryptionUnencrypted))
			})

			It("errors if the has the wrong hash", func() {
				cs.nullAEAD.(*mockcrypto.MockAEAD).EXPECT().Open(nil, []byte("not unencrypted"), protocol.PacketNumber(5), []byte{}).Return(nil, errors.New("authentication failed"))
				_, enc, err := cs.Open(nil, []byte("not unencrypted"), 5, []byte{})
				Expect(err).To(MatchError("authentication failed"))
				Expect(enc).To(Equal(protocol.EncryptionUnspecified))
			})

			It("is still accepted after CHLO", func() {
				doCHLO()
				// it tries forward secure and secure decryption first
				cs.forwardSecureAEAD.(*mockcrypto.MockAEAD).EXPECT().Open(nil, []byte("unencrypted"), protocol.PacketNumber(99), []byte{}).Return(nil, errors.New("authentication failed"))
				cs.secureAEAD.(*mockcrypto.MockAEAD).EXPECT().Open(nil, []byte("unencrypted"), protocol.PacketNumber(99), []byte{}).Return(nil, errors.New("authentication failed"))
				cs.nullAEAD.(*mockcrypto.MockAEAD).EXPECT().Open(nil, []byte("unencrypted"), protocol.PacketNumber(99), []byte{})
				Expect(cs.secureAEAD).ToNot(BeNil())
				_, enc, err := cs.Open(nil, []byte("unencrypted"), 99, []byte{})
				Expect(err).ToNot(HaveOccurred())
				Expect(enc).To(Equal(protocol.EncryptionUnencrypted))
			})

			It("is not accepted after receiving secure packet", func() {
				doCHLO()
				// first receive a secure packet
				cs.forwardSecureAEAD.(*mockcrypto.MockAEAD).EXPECT().Open(nil, []byte("encrypted"), protocol.PacketNumber(98), []byte{}).Return(nil, errors.New("authentication failed"))
				cs.secureAEAD.(*mockcrypto.MockAEAD).EXPECT().Open(nil, []byte("encrypted"), protocol.PacketNumber(98), []byte{}).Return([]byte("decrypted"), nil)
				d, enc, err := cs.Open(nil, []byte("encrypted"), 98, []byte{})
				Expect(enc).To(Equal(protocol.EncryptionSecure))
				Expect(err).ToNot(HaveOccurred())
				Expect(d).To(Equal([]byte("decrypted")))
				// now receive an unencrypted packet
				cs.forwardSecureAEAD.(*mockcrypto.MockAEAD).EXPECT().Open(nil, []byte("unencrypted"), protocol.PacketNumber(99), []byte{}).Return(nil, errors.New("authentication failed"))
				cs.secureAEAD.(*mockcrypto.MockAEAD).EXPECT().Open(nil, []byte("unencrypted"), protocol.PacketNumber(99), []byte{}).Return(nil, errors.New("authentication failed"))
				_, enc, err = cs.Open(nil, []byte("unencrypted"), 99, []byte{})
				Expect(err).To(MatchError("authentication failed"))
				Expect(enc).To(Equal(protocol.EncryptionUnspecified))
			})

			It("is not used after CHLO", func() {
				doCHLO()
				cs.forwardSecureAEAD.(*mockcrypto.MockAEAD).EXPECT().Seal(nil, []byte("foobar"), protocol.PacketNumber(0), []byte{})
				enc, sealer := cs.GetSealer()
				Expect(enc).ToNot(Equal(protocol.EncryptionUnencrypted))
				sealer.Seal(nil, []byte("foobar"), 0, []byte{})
			})
		})

		Context("initial encryption", func() {
			It("is accepted after CHLO", func() {
				doCHLO()
				cs.forwardSecureAEAD.(*mockcrypto.MockAEAD).EXPECT().Open(nil, []byte("encrypted"), protocol.PacketNumber(98), []byte{}).Return(nil, errors.New("authentication failed"))
				cs.secureAEAD.(*mockcrypto.MockAEAD).EXPECT().Open(nil, []byte("encrypted"), protocol.PacketNumber(98), []byte{}).Return([]byte("decrypted"), nil)
				d, enc, err := cs.Open(nil, []byte("encrypted"), 98, []byte{})
				Expect(enc).To(Equal(protocol.EncryptionSecure))
				Expect(err).ToNot(HaveOccurred())
				Expect(d).To(Equal([]byte("decrypted")))
			})

			It("is not accepted after receiving forward secure packet", func() {
				doCHLO()
				// receive a forward secure packet
				cs.forwardSecureAEAD.(*mockcrypto.MockAEAD).EXPECT().Open(nil, []byte("forward secure encrypted"), protocol.PacketNumber(11), []byte{})
				_, _, err := cs.Open(nil, []byte("forward secure encrypted"), 11, []byte{})
				Expect(err).ToNot(HaveOccurred())
				// receive a secure packet
				cs.forwardSecureAEAD.(*mockcrypto.MockAEAD).EXPECT().Open(nil, []byte("encrypted"), protocol.PacketNumber(12), []byte{}).Return(nil, errors.New("authentication failed"))
				_, enc, err := cs.Open(nil, []byte("encrypted"), 12, []byte{})
				Expect(err).To(MatchError("authentication failed"))
				Expect(enc).To(Equal(protocol.EncryptionUnspecified))
			})

			It("is used for the crypto stream", func() {
				doCHLO()
				cs.secureAEAD.(*mockcrypto.MockAEAD).EXPECT().Seal(nil, []byte("foobar"), protocol.PacketNumber(1), []byte{}).Return([]byte("foobar crypto stream"))
				enc, sealer := cs.GetSealerForCryptoStream()
				Expect(enc).To(Equal(protocol.EncryptionSecure))
				d := sealer.Seal(nil, []byte("foobar"), 1, []byte{})
				Expect(d).To(Equal([]byte("foobar crypto stream")))
			})
		})

		Context("forward secure encryption", func() {
			It("is used after the CHLO", func() {
				doCHLO()
				cs.forwardSecureAEAD.(*mockcrypto.MockAEAD).EXPECT().Seal(nil, []byte("foobar"), protocol.PacketNumber(20), []byte{}).Return([]byte("foobar forward sec"))
				enc, sealer := cs.GetSealer()
				Expect(enc).To(Equal(protocol.EncryptionForwardSecure))
				d := sealer.Seal(nil, []byte("foobar"), 20, []byte{})
				Expect(d).To(Equal([]byte("foobar forward sec")))
			})

			It("regards the handshake as complete once it receives a forward encrypted packet", func() {
				doCHLO()
				cs.forwardSecureAEAD.(*mockcrypto.MockAEAD).EXPECT().Open(nil, []byte("forward secure encrypted"), protocol.PacketNumber(200), []byte{})
				_, _, err := cs.Open(nil, []byte("forward secure encrypted"), 200, []byte{})
				Expect(err).ToNot(HaveOccurred())
				Expect(handshakeEvent).To(BeClosed())
			})
		})

		Context("reporting the connection state", func() {
			It("reports before the handshake completes", func() {
				cs.sni = "server name"
				state := cs.ConnectionState()
				Expect(state.HandshakeComplete).To(BeFalse())
				Expect(state.ServerName).To(Equal("server name"))
			})

			It("reports after the handshake completes", func() {
				doCHLO()
				// receive a forward secure packet
				cs.forwardSecureAEAD.(*mockcrypto.MockAEAD).EXPECT().Open(nil, []byte("forward secure encrypted"), protocol.PacketNumber(11), []byte{})
				_, _, err := cs.Open(nil, []byte("forward secure encrypted"), 11, []byte{})
				Expect(err).ToNot(HaveOccurred())
				state := cs.ConnectionState()
				Expect(state.HandshakeComplete).To(BeTrue())
			})
		})

		Context("forcing encryption levels", func() {
			It("forces null encryption", func() {
				cs.nullAEAD.(*mockcrypto.MockAEAD).EXPECT().Seal(nil, []byte("foobar"), protocol.PacketNumber(11), []byte{}).Return([]byte("foobar unencrypted"))
				sealer, err := cs.GetSealerWithEncryptionLevel(protocol.EncryptionUnencrypted)
				Expect(err).ToNot(HaveOccurred())
				d := sealer.Seal(nil, []byte("foobar"), 11, []byte{})
				Expect(d).To(Equal([]byte("foobar unencrypted")))
			})

			It("forces initial encryption", func() {
				doCHLO()
				cs.secureAEAD.(*mockcrypto.MockAEAD).EXPECT().Seal(nil, []byte("foobar"), protocol.PacketNumber(12), []byte{}).Return([]byte("foobar secure"))
				sealer, err := cs.GetSealerWithEncryptionLevel(protocol.EncryptionSecure)
				Expect(err).ToNot(HaveOccurred())
				d := sealer.Seal(nil, []byte("foobar"), 12, []byte{})
				Expect(d).To(Equal([]byte("foobar secure")))
			})

			It("errors if no AEAD for initial encryption is available", func() {
				sealer, err := cs.GetSealerWithEncryptionLevel(protocol.EncryptionSecure)
				Expect(err).To(MatchError("CryptoSetupServer: no secureAEAD"))
				Expect(sealer).To(BeNil())
			})

			It("forces forward-secure encryption", func() {
				doCHLO()
				cs.forwardSecureAEAD.(*mockcrypto.MockAEAD).EXPECT().Seal(nil, []byte("foobar"), protocol.PacketNumber(13), []byte{}).Return([]byte("foobar forward sec"))
				sealer, err := cs.GetSealerWithEncryptionLevel(protocol.EncryptionForwardSecure)
				Expect(err).ToNot(HaveOccurred())
				d := sealer.Seal(nil, []byte("foobar"), 13, []byte{})
				Expect(d).To(Equal([]byte("foobar forward sec")))
			})

			It("errors of no AEAD for forward-secure encryption is available", func() {
				seal, err := cs.GetSealerWithEncryptionLevel(protocol.EncryptionForwardSecure)
				Expect(err).To(MatchError("CryptoSetupServer: no forwardSecureAEAD"))
				Expect(seal).To(BeNil())
			})

			It("errors if no encryption level is specified", func() {
				seal, err := cs.GetSealerWithEncryptionLevel(protocol.EncryptionUnspecified)
				Expect(err).To(MatchError("CryptoSetupServer: no encryption level specified"))
				Expect(seal).To(BeNil())
			})
		})
	})

	Context("STK verification and creation", func() {
		It("requires STK", func() {
			sourceAddrValid = false
			done, err := cs.handleMessage(
				bytes.Repeat([]byte{'a'}, protocol.MinClientHelloSize),
				map[Tag][]byte{
					TagSNI: []byte("foo"),
					TagVER: versionTag,
				},
			)
			Expect(err).ToNot(HaveOccurred())
			Expect(done).To(BeFalse())
			Expect(stream.dataWritten.Bytes()).To(ContainSubstring(string(validSTK)))
			Expect(cs.sni).To(Equal("foo"))
		})

		It("works with proper STK", func() {
			sourceAddrValid = true
			done, err := cs.handleMessage(
				bytes.Repeat([]byte{'a'}, protocol.MinClientHelloSize),
				map[Tag][]byte{
					TagSNI: []byte("foo"),
					TagVER: versionTag,
				},
			)
			Expect(err).ToNot(HaveOccurred())
			Expect(done).To(BeFalse())
		})
	})
})
