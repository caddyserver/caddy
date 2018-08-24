package handshake

import (
	"bytes"
	"crypto/x509"
	"encoding/binary"
	"errors"
	"fmt"
	"time"

	"github.com/lucas-clemente/quic-go/internal/crypto"
	"github.com/lucas-clemente/quic-go/internal/mocks/crypto"
	"github.com/lucas-clemente/quic-go/internal/protocol"
	"github.com/lucas-clemente/quic-go/internal/testdata"
	"github.com/lucas-clemente/quic-go/internal/utils"
	"github.com/lucas-clemente/quic-go/qerr"
	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"
)

type keyDerivationValues struct {
	forwardSecure bool
	sharedSecret  []byte
	nonces        []byte
	connID        protocol.ConnectionID
	chlo          []byte
	scfg          []byte
	cert          []byte
	divNonce      []byte
	pers          protocol.Perspective
}

type mockCertManager struct {
	setDataCalledWith []byte
	setDataError      error

	commonCertificateHashes []byte

	chain []*x509.Certificate

	leafCert          []byte
	leafCertHash      uint64
	leafCertHashError error

	verifyServerProofResult bool
	verifyServerProofCalled bool

	verifyError  error
	verifyCalled bool
}

var _ crypto.CertManager = &mockCertManager{}

func (m *mockCertManager) SetData(data []byte) error {
	m.setDataCalledWith = data
	return m.setDataError
}

func (m *mockCertManager) GetCommonCertificateHashes() []byte {
	return m.commonCertificateHashes
}

func (m *mockCertManager) GetLeafCert() []byte {
	return m.leafCert
}

func (m *mockCertManager) GetLeafCertHash() (uint64, error) {
	return m.leafCertHash, m.leafCertHashError
}

func (m *mockCertManager) VerifyServerProof(proof, chlo, serverConfigData []byte) bool {
	m.verifyServerProofCalled = true
	return m.verifyServerProofResult
}

func (m *mockCertManager) Verify(hostname string) error {
	m.verifyCalled = true
	return m.verifyError
}

func (m *mockCertManager) GetChain() []*x509.Certificate {
	return m.chain
}

var _ = Describe("Client Crypto Setup", func() {
	var (
		cs                      *cryptoSetupClient
		certManager             *mockCertManager
		stream                  *mockStream
		keyDerivationCalledWith *keyDerivationValues
		shloMap                 map[Tag][]byte
		handshakeEvent          chan struct{}
		paramsChan              chan TransportParameters
	)

	BeforeEach(func() {
		shloMap = map[Tag][]byte{
			TagPUBS: {0x0, 0x1, 0x2, 0x3, 0x4, 0x5, 0x6, 0x7, 0x8, 0x9, 0xa, 0xb, 0xc, 0xd, 0xe, 0xf, 0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f},
			TagVER:  {},
		}
		keyDerivation := func(forwardSecure bool, sharedSecret, nonces []byte, connID protocol.ConnectionID, chlo []byte, scfg []byte, cert []byte, divNonce []byte, pers protocol.Perspective) (crypto.AEAD, error) {
			keyDerivationCalledWith = &keyDerivationValues{
				forwardSecure: forwardSecure,
				sharedSecret:  sharedSecret,
				nonces:        nonces,
				connID:        connID,
				chlo:          chlo,
				scfg:          scfg,
				cert:          cert,
				divNonce:      divNonce,
				pers:          pers,
			}
			return mockcrypto.NewMockAEAD(mockCtrl), nil
		}

		stream = newMockStream()
		certManager = &mockCertManager{}
		version := protocol.Version39
		// use a buffered channel here, so that we can parse a SHLO without having to receive the TransportParameters to avoid blocking
		paramsChan = make(chan TransportParameters, 1)
		handshakeEvent = make(chan struct{}, 2)
		csInt, err := NewCryptoSetupClient(
			stream,
			"hostname",
			protocol.ConnectionID{1, 2, 3, 4, 5, 6, 7, 8},
			version,
			nil,
			&TransportParameters{IdleTimeout: protocol.DefaultIdleTimeout},
			paramsChan,
			handshakeEvent,
			protocol.Version39,
			nil,
			utils.DefaultLogger,
		)
		Expect(err).ToNot(HaveOccurred())
		cs = csInt.(*cryptoSetupClient)
		cs.certManager = certManager
		cs.keyDerivation = keyDerivation
		cs.nullAEAD = mockcrypto.NewMockAEAD(mockCtrl)
		cs.cryptoStream = stream
	})

	Context("Reading REJ", func() {
		var tagMap map[Tag][]byte

		BeforeEach(func() {
			tagMap = make(map[Tag][]byte)
		})

		It("rejects handshake messages with the wrong message tag", func() {
			HandshakeMessage{Tag: TagCHLO, Data: tagMap}.Write(&stream.dataToRead)
			err := cs.HandleCryptoStream()
			Expect(err).To(MatchError(qerr.InvalidCryptoMessageType))
		})

		It("errors on invalid handshake messages", func() {
			stream.dataToRead.Write([]byte("invalid message"))
			err := cs.HandleCryptoStream()
			Expect(err).To(HaveOccurred())
			Expect(err.(*qerr.QuicError).ErrorCode).To(Equal(qerr.HandshakeFailed))
		})

		It("passes the message on for parsing, and reads the source address token", func() {
			stk := []byte("foobar")
			tagMap[TagSTK] = stk
			HandshakeMessage{Tag: TagREJ, Data: tagMap}.Write(&stream.dataToRead)
			done := make(chan struct{})
			go func() {
				defer GinkgoRecover()
				err := cs.HandleCryptoStream()
				Expect(err).To(MatchError(qerr.Error(qerr.HandshakeFailed, errMockStreamClosing.Error())))
				close(done)
			}()
			Eventually(func() []byte { return cs.stk }).Should(Equal(stk))
			// make the go routine return
			stream.close()
			Eventually(done).Should(BeClosed())
		})

		It("saves the proof", func() {
			proof := []byte("signature for the server config")
			tagMap[TagPROF] = proof
			err := cs.handleREJMessage(tagMap)
			Expect(err).ToNot(HaveOccurred())
			Expect(cs.proof).To(Equal(proof))
		})

		It("saves the last sent CHLO for signature validation, when receiving the proof", func() {
			chlo := []byte("last sent CHLO")
			cs.lastSentCHLO = chlo
			err := cs.handleREJMessage(tagMap)
			Expect(err).ToNot(HaveOccurred())
			Expect(cs.chloForSignature).To(BeEmpty())
			tagMap[TagPROF] = []byte("signature")
			err = cs.handleREJMessage(tagMap)
			Expect(err).ToNot(HaveOccurred())
			Expect(cs.chloForSignature).To(Equal(chlo))
		})

		It("saves the server nonce", func() {
			nonc := []byte("servernonce")
			tagMap[TagSNO] = nonc
			err := cs.handleREJMessage(tagMap)
			Expect(err).ToNot(HaveOccurred())
			Expect(cs.sno).To(Equal(nonc))
		})

		Context("validating the Version list", func() {
			It("doesn't care about the version list if there was no version negotiation", func() {
				Expect(cs.validateVersionList([]byte{0})).To(BeTrue())
			})

			It("detects a downgrade attack if the number of versions is not equal", func() {
				cs.negotiatedVersions = []protocol.VersionNumber{protocol.VersionWhatever}
				Expect(cs.validateVersionList(bytes.Repeat([]byte{'f'}, 2*4))).To(BeFalse())
			})

			It("detects a downgrade attack", func() {
				cs.negotiatedVersions = []protocol.VersionNumber{12}
				b := &bytes.Buffer{}
				utils.BigEndian.WriteUint32(b, 11)
				Expect(cs.validateVersionList(b.Bytes())).To(BeFalse())
			})

			It("errors if the version tags are invalid", func() {
				cs.negotiatedVersions = []protocol.VersionNumber{protocol.VersionWhatever}
				Expect(cs.validateVersionList([]byte{0, 1, 2})).To(BeFalse()) // 1 byte too short
			})

			It("returns the right error when detecting a downgrade attack", func() {
				cs.negotiatedVersions = []protocol.VersionNumber{protocol.VersionWhatever}
				cs.receivedSecurePacket = true
				_, err := cs.handleSHLOMessage(map[Tag][]byte{
					TagPUBS: {0},
					TagVER:  {0, 1},
				})
				Expect(err).To(MatchError(qerr.Error(qerr.VersionNegotiationMismatch, "Downgrade attack detected")))
			})
		})

		Context("Certificates", func() {
			BeforeEach(func() {
				cs.serverConfig = &serverConfigClient{}
			})

			It("passes the certificates to the CertManager", func() {
				tagMap[TagCERT] = []byte("cert")
				err := cs.handleREJMessage(tagMap)
				Expect(err).ToNot(HaveOccurred())
				Expect(certManager.setDataCalledWith).To(Equal(tagMap[TagCERT]))
			})

			It("returns an InvalidCryptoMessageParameter error if it can't parse the cert chain", func() {
				tagMap[TagCERT] = []byte("cert")
				certManager.setDataError = errors.New("can't parse")
				err := cs.handleREJMessage(tagMap)
				Expect(err).To(MatchError(qerr.Error(qerr.InvalidCryptoMessageParameter, "Certificate data invalid")))
			})

			Context("verifying the certificate chain", func() {
				It("returns a ProofInvalid error if the certificate chain is not valid", func() {
					tagMap[TagCERT] = []byte("cert")
					certManager.verifyError = errors.New("invalid")
					err := cs.handleREJMessage(tagMap)
					Expect(err).To(MatchError(qerr.ProofInvalid))
				})

				It("verifies the certificate", func() {
					certManager.verifyServerProofResult = true
					tagMap[TagCERT] = []byte("cert")
					err := cs.handleREJMessage(tagMap)
					Expect(err).ToNot(HaveOccurred())
					Expect(certManager.verifyCalled).To(BeTrue())
				})
			})

			Context("verifying the signature", func() {
				BeforeEach(func() {
					tagMap[TagCERT] = []byte("cert")
					tagMap[TagPROF] = []byte("proof")
					certManager.leafCert = []byte("leafcert")
				})

				It("rejects wrong signature", func() {
					certManager.verifyServerProofResult = false
					err := cs.handleREJMessage(tagMap)
					Expect(err).To(MatchError(qerr.ProofInvalid))
					Expect(certManager.verifyServerProofCalled).To(BeTrue())
				})

				It("accepts correct signatures", func() {
					certManager.verifyServerProofResult = true
					err := cs.handleREJMessage(tagMap)
					Expect(err).ToNot(HaveOccurred())
					Expect(certManager.verifyServerProofCalled).To(BeTrue())
				})

				It("doesn't try to verify the signature if the certificate is missing", func() {
					delete(tagMap, TagCERT)
					certManager.leafCert = nil
					err := cs.handleREJMessage(tagMap)
					Expect(err).ToNot(HaveOccurred())
					Expect(certManager.verifyServerProofCalled).To(BeFalse())
				})

				It("doesn't try to verify the signature if the server config is missing", func() {
					cs.serverConfig = nil
					err := cs.handleREJMessage(tagMap)
					Expect(err).ToNot(HaveOccurred())
					Expect(certManager.verifyServerProofCalled).To(BeFalse())
				})

				It("doesn't try to verify the signature if the signature is missing", func() {
					delete(tagMap, TagPROF)
					err := cs.handleREJMessage(tagMap)
					Expect(err).ToNot(HaveOccurred())
					Expect(certManager.verifyServerProofCalled).To(BeFalse())
				})
			})
		})

		Context("Reading server configs", func() {
			It("reads a server config", func() {
				b := &bytes.Buffer{}
				scfg := getDefaultServerConfigClient()
				HandshakeMessage{Tag: TagSCFG, Data: scfg}.Write(b)
				tagMap[TagSCFG] = b.Bytes()
				err := cs.handleREJMessage(tagMap)
				Expect(err).ToNot(HaveOccurred())
				Expect(cs.serverConfig).ToNot(BeNil())
				Expect(cs.serverConfig.ID).To(Equal(scfg[TagSCID]))
			})

			It("rejects expired server configs", func() {
				b := &bytes.Buffer{}
				scfg := getDefaultServerConfigClient()
				scfg[TagEXPY] = []byte{0x80, 0x54, 0x72, 0x4F, 0, 0, 0, 0} // 2012-03-28
				HandshakeMessage{Tag: TagSCFG, Data: scfg}.Write(b)
				tagMap[TagSCFG] = b.Bytes()
				// make sure we actually set TagEXPY correct
				serverConfig, err := parseServerConfig(b.Bytes())
				Expect(err).ToNot(HaveOccurred())
				Expect(serverConfig.expiry.Year()).To(Equal(2012))
				// now try to read this server config in the crypto setup
				err = cs.handleREJMessage(tagMap)
				Expect(err).To(MatchError(qerr.CryptoServerConfigExpired))
			})

			It("generates a client nonce after reading a server config", func() {
				b := &bytes.Buffer{}
				HandshakeMessage{Tag: TagSCFG, Data: getDefaultServerConfigClient()}.Write(b)
				tagMap[TagSCFG] = b.Bytes()
				err := cs.handleREJMessage(tagMap)
				Expect(err).ToNot(HaveOccurred())
				Expect(cs.nonc).To(HaveLen(32))
			})

			It("only generates a client nonce once, when reading multiple server configs", func() {
				b := &bytes.Buffer{}
				HandshakeMessage{Tag: TagSCFG, Data: getDefaultServerConfigClient()}.Write(b)
				tagMap[TagSCFG] = b.Bytes()
				err := cs.handleREJMessage(tagMap)
				Expect(err).ToNot(HaveOccurred())
				nonc := cs.nonc
				Expect(nonc).ToNot(BeEmpty())
				err = cs.handleREJMessage(tagMap)
				Expect(err).ToNot(HaveOccurred())
				Expect(cs.nonc).To(Equal(nonc))
			})

			It("passes on errors from reading the server config", func() {
				b := &bytes.Buffer{}
				HandshakeMessage{Tag: TagSHLO, Data: make(map[Tag][]byte)}.Write(b)
				tagMap[TagSCFG] = b.Bytes()
				_, origErr := parseServerConfig(b.Bytes())
				err := cs.handleREJMessage(tagMap)
				Expect(err).To(HaveOccurred())
				Expect(err).To(MatchError(origErr))
			})
		})
	})

	Context("Reading SHLO", func() {
		BeforeEach(func() {
			kex, err := crypto.NewCurve25519KEX()
			Expect(err).ToNot(HaveOccurred())
			serverConfig := &serverConfigClient{
				kex: kex,
			}
			cs.serverConfig = serverConfig
			cs.receivedSecurePacket = true
		})

		It("rejects unencrypted SHLOs", func() {
			cs.receivedSecurePacket = false
			_, err := cs.handleSHLOMessage(shloMap)
			Expect(err).To(MatchError(qerr.Error(qerr.CryptoEncryptionLevelIncorrect, "unencrypted SHLO message")))
			Expect(handshakeEvent).ToNot(Receive())
			Expect(handshakeEvent).ToNot(BeClosed())
		})

		It("rejects SHLOs without a PUBS", func() {
			delete(shloMap, TagPUBS)
			_, err := cs.handleSHLOMessage(shloMap)
			Expect(err).To(MatchError(qerr.Error(qerr.CryptoMessageParameterNotFound, "PUBS")))
			Expect(handshakeEvent).ToNot(BeClosed())
		})

		It("rejects SHLOs without a version list", func() {
			delete(shloMap, TagVER)
			_, err := cs.handleSHLOMessage(shloMap)
			Expect(err).To(MatchError(qerr.Error(qerr.InvalidCryptoMessageParameter, "server hello missing version list")))
			Expect(handshakeEvent).ToNot(BeClosed())
		})

		It("accepts a SHLO after a version negotiation", func() {
			ver := protocol.SupportedVersions[0]
			cs.negotiatedVersions = []protocol.VersionNumber{ver}
			cs.receivedSecurePacket = true
			b := &bytes.Buffer{}
			utils.BigEndian.WriteUint32(b, uint32(ver))
			shloMap[TagVER] = b.Bytes()
			_, err := cs.handleSHLOMessage(shloMap)
			Expect(err).ToNot(HaveOccurred())
		})

		It("reads the server nonce, if set", func() {
			shloMap[TagSNO] = []byte("server nonce")
			_, err := cs.handleSHLOMessage(shloMap)
			Expect(err).ToNot(HaveOccurred())
			Expect(cs.sno).To(Equal(shloMap[TagSNO]))
		})

		It("creates a forwardSecureAEAD", func() {
			shloMap[TagSNO] = []byte("server nonce")
			_, err := cs.handleSHLOMessage(shloMap)
			Expect(err).ToNot(HaveOccurred())
			Expect(cs.forwardSecureAEAD).ToNot(BeNil())
		})

		It("reads the connection parameters", func() {
			shloMap[TagICSL] = []byte{13, 0, 0, 0} // 13 seconds
			params, err := cs.handleSHLOMessage(shloMap)
			Expect(err).ToNot(HaveOccurred())
			Expect(params.IdleTimeout).To(Equal(13 * time.Second))
		})

		It("closes the handshakeEvent chan when receiving an SHLO", func() {
			HandshakeMessage{Tag: TagSHLO, Data: shloMap}.Write(&stream.dataToRead)
			done := make(chan struct{})
			go func() {
				defer GinkgoRecover()
				err := cs.HandleCryptoStream()
				Expect(err).To(MatchError(qerr.Error(qerr.HandshakeFailed, errMockStreamClosing.Error())))
				close(done)
			}()
			Eventually(handshakeEvent).Should(Receive())
			Eventually(handshakeEvent).Should(BeClosed())
			// make the go routine return
			stream.close()
			Eventually(done).Should(BeClosed())
		})

		It("passes the transport parameters on the channel", func() {
			shloMap[TagSFCW] = []byte{0x0d, 0x00, 0xdf, 0xba}
			HandshakeMessage{Tag: TagSHLO, Data: shloMap}.Write(&stream.dataToRead)
			done := make(chan struct{})
			go func() {
				defer GinkgoRecover()
				err := cs.HandleCryptoStream()
				Expect(err).To(MatchError(qerr.Error(qerr.HandshakeFailed, errMockStreamClosing.Error())))
				close(done)
			}()
			var params TransportParameters
			Eventually(paramsChan).Should(Receive(&params))
			Expect(params.StreamFlowControlWindow).To(Equal(protocol.ByteCount(0xbadf000d)))
			// make the go routine return
			stream.close()
			Eventually(done).Should(BeClosed())
		})

		It("errors if it can't read a connection parameter", func() {
			shloMap[TagICSL] = []byte{3, 0, 0} // 1 byte too short
			_, err := cs.handleSHLOMessage(shloMap)
			Expect(err).To(MatchError(qerr.InvalidCryptoMessageParameter))
		})
	})

	Context("CHLO generation", func() {
		It("is longer than the miminum client hello size", func() {
			err := cs.sendCHLO()
			Expect(err).ToNot(HaveOccurred())
			Expect(cs.cryptoStream.(*mockStream).dataWritten.Len()).To(BeNumerically(">", protocol.MinClientHelloSize))
		})

		It("doesn't overflow the packet with padding", func() {
			tagMap := make(map[Tag][]byte)
			tagMap[TagSCID] = bytes.Repeat([]byte{0}, protocol.MinClientHelloSize*6/10)
			cs.addPadding(tagMap)
			Expect(len(tagMap[TagPAD])).To(BeNumerically("<", protocol.MinClientHelloSize/2))
		})

		It("saves the last sent CHLO", func() {
			// send first CHLO
			err := cs.sendCHLO()
			Expect(err).ToNot(HaveOccurred())
			Expect(cs.cryptoStream.(*mockStream).dataWritten.Bytes()).To(Equal(cs.lastSentCHLO))
			cs.cryptoStream.(*mockStream).dataWritten.Reset()
			firstCHLO := cs.lastSentCHLO
			// send second CHLO
			cs.sno = []byte("foobar")
			err = cs.sendCHLO()
			Expect(err).ToNot(HaveOccurred())
			Expect(cs.cryptoStream.(*mockStream).dataWritten.Bytes()).To(Equal(cs.lastSentCHLO))
			Expect(cs.lastSentCHLO).ToNot(Equal(firstCHLO))
		})

		It("has the right values for an inchoate CHLO", func() {
			cs.version = cs.initialVersion - 1
			cs.hostname = "sni-hostname"
			certManager.commonCertificateHashes = []byte("common certs")
			tags, err := cs.getTags()
			Expect(err).ToNot(HaveOccurred())
			Expect(string(tags[TagSNI])).To(Equal(cs.hostname))
			Expect(tags[TagPDMD]).To(Equal([]byte("X509")))
			Expect(tags[TagVER]).To(Equal([]byte("Q039")))
			Expect(tags[TagCCS]).To(Equal(certManager.commonCertificateHashes))
			Expect(tags).ToNot(HaveKey(TagTCID))
		})

		It("requests to omit the connection ID", func() {
			cs.params.OmitConnectionID = true
			tags, err := cs.getTags()
			Expect(err).ToNot(HaveOccurred())
			Expect(tags).To(HaveKeyWithValue(TagTCID, []byte{0, 0, 0, 0}))
		})

		It("adds the tags returned from the connectionParametersManager to the CHLO", func() {
			pnTags := cs.params.getHelloMap()
			Expect(pnTags).ToNot(BeEmpty())
			tags, err := cs.getTags()
			Expect(err).ToNot(HaveOccurred())
			for t := range pnTags {
				Expect(tags).To(HaveKey(t))
			}
		})

		It("doesn't send a CCS if there are no common certificate sets available", func() {
			certManager.commonCertificateHashes = nil
			tags, err := cs.getTags()
			Expect(err).ToNot(HaveOccurred())
			Expect(tags).ToNot(HaveKey(TagCCS))
		})

		It("includes the server config id, if available", func() {
			id := []byte("foobar")
			cs.serverConfig = &serverConfigClient{ID: id}
			tags, err := cs.getTags()
			Expect(err).ToNot(HaveOccurred())
			Expect(tags[TagSCID]).To(Equal(id))
		})

		It("includes the source address token, if available", func() {
			cs.stk = []byte("sourceaddresstoken")
			tags, err := cs.getTags()
			Expect(err).ToNot(HaveOccurred())
			Expect(tags[TagSTK]).To(Equal(cs.stk))
		})

		It("includes the server nonce, if available", func() {
			cs.sno = []byte("foobar")
			tags, err := cs.getTags()
			Expect(err).ToNot(HaveOccurred())
			Expect(tags[TagSNO]).To(Equal(cs.sno))
		})

		It("doesn't include optional values, if not available", func() {
			tags, err := cs.getTags()
			Expect(err).ToNot(HaveOccurred())
			Expect(tags).ToNot(HaveKey(TagSCID))
			Expect(tags).ToNot(HaveKey(TagSNO))
			Expect(tags).ToNot(HaveKey(TagSTK))
		})

		It("doesn't change any values after reading the certificate, if the server config is missing", func() {
			tags, err := cs.getTags()
			Expect(err).ToNot(HaveOccurred())
			certManager.leafCert = []byte("leafcert")
			Expect(cs.getTags()).To(Equal(tags))
		})

		It("sends a the values needed for a full CHLO after reading the certificate and the server config", func() {
			certManager.leafCert = []byte("leafcert")
			cs.nonc = []byte("client-nonce")
			kex, err := crypto.NewCurve25519KEX()
			Expect(err).ToNot(HaveOccurred())
			cs.serverConfig = &serverConfigClient{kex: kex}
			xlct := []byte{0x1, 0x2, 0x3, 0x4, 0x5, 0x6, 0x7, 0x8}
			certManager.leafCertHash = binary.LittleEndian.Uint64(xlct)
			tags, err := cs.getTags()
			Expect(err).ToNot(HaveOccurred())
			Expect(tags[TagNONC]).To(Equal(cs.nonc))
			Expect(tags[TagPUBS]).To(Equal(kex.PublicKey()))
			Expect(tags[TagXLCT]).To(Equal(xlct))
			Expect(tags[TagKEXS]).To(Equal([]byte("C255")))
			Expect(tags[TagAEAD]).To(Equal([]byte("AESG")))
		})

		It("doesn't send more than MaxClientHellos CHLOs", func() {
			Expect(cs.clientHelloCounter).To(BeZero())
			for i := 1; i <= protocol.MaxClientHellos; i++ {
				err := cs.sendCHLO()
				Expect(err).ToNot(HaveOccurred())
				Expect(cs.clientHelloCounter).To(Equal(i))
			}
			err := cs.sendCHLO()
			Expect(err).To(MatchError(qerr.Error(qerr.CryptoTooManyRejects, fmt.Sprintf("More than %d rejects", protocol.MaxClientHellos))))
		})
	})

	Context("escalating crypto", func() {
		doCompleteREJ := func() {
			cs.serverVerified = true
			err := cs.maybeUpgradeCrypto()
			Expect(err).ToNot(HaveOccurred())
			Expect(cs.secureAEAD).ToNot(BeNil())
		}

		doSHLO := func() {
			cs.receivedSecurePacket = true
			_, err := cs.handleSHLOMessage(shloMap)
			Expect(err).ToNot(HaveOccurred())
		}

		// sets all values necessary for escalating to secureAEAD
		BeforeEach(func() {
			kex, err := crypto.NewCurve25519KEX()
			Expect(err).ToNot(HaveOccurred())
			cs.serverConfig = &serverConfigClient{
				kex:          kex,
				obit:         []byte("obit"),
				sharedSecret: []byte("sharedSecret"),
				raw:          []byte("rawserverconfig"),
			}
			cs.lastSentCHLO = []byte("lastSentCHLO")
			cs.nonc = []byte("nonc")
			cs.diversificationNonce = []byte("divnonce")
			certManager.leafCert = []byte("leafCert")
		})

		It("creates a secureAEAD once it has all necessary values", func() {
			cs.serverVerified = true
			err := cs.maybeUpgradeCrypto()
			Expect(err).ToNot(HaveOccurred())
			Expect(cs.secureAEAD).ToNot(BeNil())
			Expect(keyDerivationCalledWith.forwardSecure).To(BeFalse())
			Expect(keyDerivationCalledWith.sharedSecret).To(Equal(cs.serverConfig.sharedSecret))
			Expect(keyDerivationCalledWith.nonces).To(Equal(cs.nonc))
			Expect(keyDerivationCalledWith.connID).To(Equal(cs.connID))
			Expect(keyDerivationCalledWith.chlo).To(Equal(cs.lastSentCHLO))
			Expect(keyDerivationCalledWith.scfg).To(Equal(cs.serverConfig.Get()))
			Expect(keyDerivationCalledWith.cert).To(Equal(certManager.leafCert))
			Expect(keyDerivationCalledWith.divNonce).To(Equal(cs.diversificationNonce))
			Expect(keyDerivationCalledWith.pers).To(Equal(protocol.PerspectiveClient))
			Expect(handshakeEvent).To(Receive())
			Expect(handshakeEvent).ToNot(Receive())
			Expect(handshakeEvent).ToNot(BeClosed())
		})

		It("uses the server nonce, if the server sent one", func() {
			cs.serverVerified = true
			cs.sno = []byte("server nonce")
			err := cs.maybeUpgradeCrypto()
			Expect(err).ToNot(HaveOccurred())
			Expect(cs.secureAEAD).ToNot(BeNil())
			Expect(keyDerivationCalledWith.nonces).To(Equal(append(cs.nonc, cs.sno...)))
			Expect(handshakeEvent).To(Receive())
			Expect(handshakeEvent).ToNot(Receive())
			Expect(handshakeEvent).ToNot(BeClosed())
		})

		It("doesn't create a secureAEAD if the certificate is not yet verified, even if it has all necessary values", func() {
			err := cs.maybeUpgradeCrypto()
			Expect(err).ToNot(HaveOccurred())
			Expect(cs.secureAEAD).To(BeNil())
			Expect(handshakeEvent).ToNot(Receive())
			cs.serverVerified = true
			// make sure we really had all necessary values before, and only serverVerified was missing
			err = cs.maybeUpgradeCrypto()
			Expect(err).ToNot(HaveOccurred())
			Expect(cs.secureAEAD).ToNot(BeNil())
			Expect(handshakeEvent).To(Receive())
			Expect(handshakeEvent).ToNot(Receive())
			Expect(handshakeEvent).ToNot(BeClosed())
		})

		It("tries to escalate before reading a handshake message", func() {
			Expect(cs.secureAEAD).To(BeNil())
			cs.serverVerified = true
			done := make(chan struct{})
			go func() {
				defer GinkgoRecover()
				err := cs.HandleCryptoStream()
				Expect(err).To(MatchError(qerr.Error(qerr.HandshakeFailed, errMockStreamClosing.Error())))
				close(done)
			}()
			Eventually(handshakeEvent).Should(Receive())
			Expect(cs.secureAEAD).ToNot(BeNil())
			Expect(handshakeEvent).ToNot(Receive())
			Expect(handshakeEvent).ToNot(BeClosed())
			// make the go routine return
			stream.close()
			Eventually(done).Should(BeClosed())
		})

		It("tries to escalate the crypto after receiving a diversification nonce", func() {
			done := make(chan struct{})
			cs.diversificationNonce = nil
			cs.serverVerified = true
			go func() {
				defer GinkgoRecover()
				err := cs.HandleCryptoStream()
				Expect(err).To(MatchError(qerr.Error(qerr.HandshakeFailed, errMockStreamClosing.Error())))
				close(done)
			}()
			Expect(cs.secureAEAD).To(BeNil())
			Expect(cs.SetDiversificationNonce([]byte("div"))).To(Succeed())
			Eventually(handshakeEvent).Should(Receive())
			Expect(cs.secureAEAD).ToNot(BeNil())
			Expect(handshakeEvent).ToNot(Receive())
			Expect(handshakeEvent).ToNot(BeClosed())
			// make the go routine return
			stream.close()
			Eventually(done).Should(BeClosed())
		})

		Context("null encryption", func() {
			It("is used initially", func() {
				cs.nullAEAD.(*mockcrypto.MockAEAD).EXPECT().Seal(nil, []byte("foobar"), protocol.PacketNumber(10), []byte{}).Return([]byte("foobar unencrypted"))
				enc, sealer := cs.GetSealer()
				Expect(enc).To(Equal(protocol.EncryptionUnencrypted))
				d := sealer.Seal(nil, []byte("foobar"), 10, []byte{})
				Expect(d).To(Equal([]byte("foobar unencrypted")))
			})

			It("is used for the crypto stream", func() {
				cs.nullAEAD.(*mockcrypto.MockAEAD).EXPECT().Seal(nil, []byte("foobar"), protocol.PacketNumber(1), []byte{}).Return([]byte("foobar unencrypted"))
				enc, sealer := cs.GetSealerForCryptoStream()
				Expect(enc).To(Equal(protocol.EncryptionUnencrypted))
				d := sealer.Seal(nil, []byte("foobar"), 1, []byte{})
				Expect(d).To(Equal([]byte("foobar unencrypted")))
			})

			It("is accepted initially", func() {
				cs.nullAEAD.(*mockcrypto.MockAEAD).EXPECT().Open(nil, []byte("unencrypted"), protocol.PacketNumber(1), []byte{}).Return([]byte("decrypted"), nil)
				d, enc, err := cs.Open(nil, []byte("unencrypted"), 1, []byte{})
				Expect(err).ToNot(HaveOccurred())
				Expect(d).To(Equal([]byte("decrypted")))
				Expect(enc).To(Equal(protocol.EncryptionUnencrypted))
			})

			It("is accepted before the server sent an encrypted packet", func() {
				doCompleteREJ()
				cs.secureAEAD.(*mockcrypto.MockAEAD).EXPECT().Open(nil, []byte("unencrypted"), protocol.PacketNumber(1), []byte{}).Return(nil, errors.New("authentication failed"))
				cs.nullAEAD.(*mockcrypto.MockAEAD).EXPECT().Open(nil, []byte("unencrypted"), protocol.PacketNumber(1), []byte{}).Return([]byte("decrypted"), nil)
				cs.receivedSecurePacket = false
				Expect(cs.secureAEAD).ToNot(BeNil())
				d, enc, err := cs.Open(nil, []byte("unencrypted"), 1, []byte{})
				Expect(err).ToNot(HaveOccurred())
				Expect(d).To(Equal([]byte("decrypted")))
				Expect(enc).To(Equal(protocol.EncryptionUnencrypted))
			})

			It("is not accepted after the server sent an encrypted packet", func() {
				doCompleteREJ()
				cs.secureAEAD.(*mockcrypto.MockAEAD).EXPECT().Open(nil, []byte("unencrypted"), protocol.PacketNumber(3), []byte{}).Return(nil, errors.New("authentication failed"))
				cs.receivedSecurePacket = true
				_, enc, err := cs.Open(nil, []byte("unencrypted"), 3, []byte{})
				Expect(err).To(MatchError("authentication failed"))
				Expect(enc).To(Equal(protocol.EncryptionUnspecified))
			})

			It("errors if the has the wrong hash", func() {
				cs.nullAEAD.(*mockcrypto.MockAEAD).EXPECT().Open(nil, []byte("not unencrypted"), protocol.PacketNumber(3), []byte{}).Return(nil, errors.New("authentication failed"))
				_, enc, err := cs.Open(nil, []byte("not unencrypted"), 3, []byte{})
				Expect(err).To(MatchError("authentication failed"))
				Expect(enc).To(Equal(protocol.EncryptionUnspecified))
			})
		})

		Context("initial encryption", func() {
			It("is used immediately when available", func() {
				doCompleteREJ()
				cs.secureAEAD.(*mockcrypto.MockAEAD).EXPECT().Seal(nil, []byte("foobar"), protocol.PacketNumber(1), []byte{}).Return([]byte("foobar secure"))
				cs.receivedSecurePacket = false
				enc, sealer := cs.GetSealer()
				Expect(enc).To(Equal(protocol.EncryptionSecure))
				d := sealer.Seal(nil, []byte("foobar"), 1, []byte{})
				Expect(d).To(Equal([]byte("foobar secure")))
			})

			It("is accepted", func() {
				doCompleteREJ()
				cs.secureAEAD.(*mockcrypto.MockAEAD).EXPECT().Open(nil, []byte("encrypted"), protocol.PacketNumber(3), []byte{}).Return([]byte("decrypted"), nil)
				d, enc, err := cs.Open(nil, []byte("encrypted"), 3, []byte{})
				Expect(err).ToNot(HaveOccurred())
				Expect(d).To(Equal([]byte("decrypted")))
				Expect(enc).To(Equal(protocol.EncryptionSecure))
				Expect(cs.receivedSecurePacket).To(BeTrue())
			})

			It("is not used after receiving the SHLO", func() {
				doSHLO()
				cs.forwardSecureAEAD.(*mockcrypto.MockAEAD).EXPECT().Open(nil, []byte("encrypted"), protocol.PacketNumber(30), []byte{}).Return(nil, errors.New("authentication failed"))
				_, enc, err := cs.Open(nil, []byte("encrypted"), 30, []byte{})
				Expect(err).To(MatchError("authentication failed"))
				Expect(enc).To(Equal(protocol.EncryptionUnspecified))
			})

			It("is not used for the crypto stream", func() {
				doCompleteREJ()
				cs.nullAEAD.(*mockcrypto.MockAEAD).EXPECT().Seal(nil, []byte("foobar"), protocol.PacketNumber(3), []byte{}).Return([]byte("foobar unencrypted"))
				enc, sealer := cs.GetSealerForCryptoStream()
				Expect(enc).To(Equal(protocol.EncryptionUnencrypted))
				d := sealer.Seal(nil, []byte("foobar"), 3, []byte{})
				Expect(d).To(Equal([]byte("foobar unencrypted")))
			})
		})

		Context("forward-secure encryption", func() {
			It("is used after receiving the SHLO", func() {
				doSHLO()
				cs.forwardSecureAEAD.(*mockcrypto.MockAEAD).EXPECT().Open(nil, []byte("shlo"), protocol.PacketNumber(4), []byte{})
				cs.forwardSecureAEAD.(*mockcrypto.MockAEAD).EXPECT().Seal(nil, []byte("foobar"), protocol.PacketNumber(10), []byte{}).Return([]byte("foobar forward sec"))
				_, enc, err := cs.Open(nil, []byte("shlo"), 4, []byte{})
				Expect(err).ToNot(HaveOccurred())
				Expect(enc).To(Equal(protocol.EncryptionForwardSecure))
				enc, sealer := cs.GetSealer()
				Expect(enc).To(Equal(protocol.EncryptionForwardSecure))
				d := sealer.Seal(nil, []byte("foobar"), 10, []byte{})
				Expect(d).To(Equal([]byte("foobar forward sec")))
			})

			It("is not used for the crypto stream", func() {
				doSHLO()
				cs.nullAEAD.(*mockcrypto.MockAEAD).EXPECT().Seal(nil, []byte("foobar"), protocol.PacketNumber(3), []byte{}).Return([]byte("foobar unencrypted"))
				enc, sealer := cs.GetSealerForCryptoStream()
				Expect(enc).To(Equal(protocol.EncryptionUnencrypted))
				d := sealer.Seal(nil, []byte("foobar"), 3, []byte{})
				Expect(d).To(Equal([]byte("foobar unencrypted")))
			})
		})

		Context("reporting the connection state", func() {
			It("reports the connection state before the handshake completes", func() {
				chain := []*x509.Certificate{testdata.GetCertificate().Leaf}
				certManager.chain = chain
				state := cs.ConnectionState()
				Expect(state.HandshakeComplete).To(BeFalse())
				Expect(state.PeerCertificates).To(Equal(chain))
			})

			It("reports the connection state after the handshake completes", func() {
				doSHLO()
				state := cs.ConnectionState()
				Expect(state.HandshakeComplete).To(BeTrue())
			})
		})

		Context("forcing encryption levels", func() {
			It("forces null encryption", func() {
				cs.nullAEAD.(*mockcrypto.MockAEAD).EXPECT().Seal(nil, []byte("foobar"), protocol.PacketNumber(4), []byte{}).Return([]byte("foobar unencrypted"))
				sealer, err := cs.GetSealerWithEncryptionLevel(protocol.EncryptionUnencrypted)
				Expect(err).ToNot(HaveOccurred())
				d := sealer.Seal(nil, []byte("foobar"), 4, []byte{})
				Expect(d).To(Equal([]byte("foobar unencrypted")))
			})

			It("forces initial encryption", func() {
				doCompleteREJ()
				cs.secureAEAD.(*mockcrypto.MockAEAD).EXPECT().Seal(nil, []byte("foobar"), protocol.PacketNumber(3), []byte{}).Return([]byte("foobar secure"))
				sealer, err := cs.GetSealerWithEncryptionLevel(protocol.EncryptionSecure)
				Expect(err).ToNot(HaveOccurred())
				d := sealer.Seal(nil, []byte("foobar"), 3, []byte{})
				Expect(d).To(Equal([]byte("foobar secure")))
			})

			It("errors of no AEAD for initial encryption is available", func() {
				sealer, err := cs.GetSealerWithEncryptionLevel(protocol.EncryptionSecure)
				Expect(err).To(MatchError("CryptoSetupClient: no secureAEAD"))
				Expect(sealer).To(BeNil())
			})

			It("forces forward-secure encryption", func() {
				doSHLO()
				cs.forwardSecureAEAD.(*mockcrypto.MockAEAD).EXPECT().Seal(nil, []byte("foobar"), protocol.PacketNumber(4), []byte{}).Return([]byte("foobar forward sec"))
				sealer, err := cs.GetSealerWithEncryptionLevel(protocol.EncryptionForwardSecure)
				Expect(err).ToNot(HaveOccurred())
				d := sealer.Seal(nil, []byte("foobar"), 4, []byte{})
				Expect(d).To(Equal([]byte("foobar forward sec")))
			})

			It("errors of no AEAD for forward-secure encryption is available", func() {
				sealer, err := cs.GetSealerWithEncryptionLevel(protocol.EncryptionForwardSecure)
				Expect(err).To(MatchError("CryptoSetupClient: no forwardSecureAEAD"))
				Expect(sealer).To(BeNil())
			})

			It("errors if no encryption level is specified", func() {
				sealer, err := cs.GetSealerWithEncryptionLevel(protocol.EncryptionUnspecified)
				Expect(err).To(MatchError("CryptoSetupClient: no encryption level specified"))
				Expect(sealer).To(BeNil())
			})
		})
	})

	Context("Diversification Nonces", func() {
		It("sets a diversification nonce", func() {
			done := make(chan struct{})
			go func() {
				defer GinkgoRecover()
				err := cs.HandleCryptoStream()
				Expect(err).To(MatchError(qerr.Error(qerr.HandshakeFailed, errMockStreamClosing.Error())))
				close(done)
			}()
			nonce := []byte("foobar")
			Expect(cs.SetDiversificationNonce(nonce)).To(Succeed())
			Eventually(func() []byte { return cs.diversificationNonce }).Should(Equal(nonce))
			// make the go routine return
			stream.close()
			Eventually(done).Should(BeClosed())
		})

		It("doesn't do anything when called multiple times with the same nonce", func() {
			done := make(chan struct{})
			go func() {
				defer GinkgoRecover()
				err := cs.HandleCryptoStream()
				Expect(err).To(MatchError(qerr.Error(qerr.HandshakeFailed, errMockStreamClosing.Error())))
				close(done)
			}()
			nonce := []byte("foobar")
			Expect(cs.SetDiversificationNonce(nonce)).To(Succeed())
			Expect(cs.SetDiversificationNonce(nonce)).To(Succeed())
			Eventually(func() []byte { return cs.diversificationNonce }).Should(Equal(nonce))
			// make the go routine return
			stream.close()
			Eventually(done).Should(BeClosed())
		})

		It("rejects a different diversification nonce", func() {
			done := make(chan struct{})
			go func() {
				defer GinkgoRecover()
				err := cs.HandleCryptoStream()
				Expect(err).To(MatchError(qerr.Error(qerr.HandshakeFailed, errMockStreamClosing.Error())))
				close(done)
			}()
			nonce1 := []byte("foobar")
			nonce2 := []byte("raboof")
			err := cs.SetDiversificationNonce(nonce1)
			Expect(err).ToNot(HaveOccurred())
			err = cs.SetDiversificationNonce(nonce2)
			Expect(err).To(MatchError(errConflictingDiversificationNonces))
			// make the go routine return
			stream.close()
			Eventually(done).Should(BeClosed())
		})
	})

	Context("Client Nonce generation", func() {
		BeforeEach(func() {
			cs.serverConfig = &serverConfigClient{}
			cs.serverConfig.obit = []byte{0x1, 0x2, 0x3, 0x4, 0x5, 0x6, 0x7, 0x8}
		})

		It("generates a client nonce", func() {
			now := time.Now()
			err := cs.generateClientNonce()
			Expect(cs.nonc).To(HaveLen(32))
			Expect(err).ToNot(HaveOccurred())
			Expect(time.Unix(int64(binary.BigEndian.Uint32(cs.nonc[0:4])), 0)).To(BeTemporally("~", now, 1*time.Second))
			Expect(cs.nonc[4:12]).To(Equal(cs.serverConfig.obit))
		})

		It("uses random values for the last 20 bytes", func() {
			err := cs.generateClientNonce()
			Expect(err).ToNot(HaveOccurred())
			nonce1 := cs.nonc
			cs.nonc = []byte{}
			err = cs.generateClientNonce()
			Expect(err).ToNot(HaveOccurred())
			nonce2 := cs.nonc
			Expect(nonce1[4:12]).To(Equal(nonce2[4:12]))
			Expect(nonce1[12:]).ToNot(Equal(nonce2[12:]))
		})

		It("errors if a client nonce has already been generated", func() {
			err := cs.generateClientNonce()
			Expect(err).ToNot(HaveOccurred())
			err = cs.generateClientNonce()
			Expect(err).To(MatchError(errClientNonceAlreadyExists))
		})

		It("errors if no OBIT value is available", func() {
			cs.serverConfig.obit = []byte{}
			err := cs.generateClientNonce()
			Expect(err).To(MatchError(errNoObitForClientNonce))
		})
	})
})
