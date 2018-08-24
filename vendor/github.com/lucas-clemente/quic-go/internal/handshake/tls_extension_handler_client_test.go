package handshake

import (
	"bytes"
	"fmt"
	"time"

	"github.com/bifurcation/mint"
	"github.com/lucas-clemente/quic-go/internal/protocol"
	"github.com/lucas-clemente/quic-go/internal/utils"

	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"
)

var _ = Describe("TLS Extension Handler, for the client", func() {
	var (
		handler *extensionHandlerClient
		el      mint.ExtensionList
	)

	BeforeEach(func() {
		handler = NewExtensionHandlerClient(&TransportParameters{}, protocol.VersionWhatever, nil, protocol.VersionWhatever, utils.DefaultLogger).(*extensionHandlerClient)
		el = make(mint.ExtensionList, 0)
	})

	Context("sending", func() {
		It("only adds TransportParameters for the ClientHello", func() {
			// test 2 other handshake types
			err := handler.Send(mint.HandshakeTypeCertificateRequest, &el)
			Expect(err).ToNot(HaveOccurred())
			Expect(el).To(BeEmpty())
			err = handler.Send(mint.HandshakeTypeEndOfEarlyData, &el)
			Expect(err).ToNot(HaveOccurred())
			Expect(el).To(BeEmpty())
		})

		It("adds TransportParameters to the ClientHello", func() {
			handler.initialVersion = 13
			err := handler.Send(mint.HandshakeTypeClientHello, &el)
			Expect(err).ToNot(HaveOccurred())
			Expect(el).To(HaveLen(1))
			ext := &tlsExtensionBody{}
			found, err := el.Find(ext)
			Expect(err).ToNot(HaveOccurred())
			Expect(found).To(BeTrue())
			chtp := &clientHelloTransportParameters{}
			err = chtp.Unmarshal(ext.data)
			Expect(err).ToNot(HaveOccurred())
			Expect(chtp.InitialVersion).To(BeEquivalentTo(13))
		})
	})

	Context("receiving", func() {
		var fakeBody *tlsExtensionBody
		var parameters TransportParameters

		addEncryptedExtensionsWithParameters := func(params TransportParameters) {
			body := (&encryptedExtensionsTransportParameters{
				Parameters:        params,
				SupportedVersions: []protocol.VersionNumber{handler.version},
			}).Marshal()
			Expect(el.Add(&tlsExtensionBody{data: body})).To(Succeed())
		}

		BeforeEach(func() {
			fakeBody = &tlsExtensionBody{data: []byte("foobar foobar")}
			parameters = TransportParameters{
				IdleTimeout:         0x1337 * time.Second,
				StatelessResetToken: bytes.Repeat([]byte{0}, 16),
			}
		})

		It("blocks until the transport parameters are read", func() {
			done := make(chan struct{})
			go func() {
				defer GinkgoRecover()
				addEncryptedExtensionsWithParameters(parameters)
				err := handler.Receive(mint.HandshakeTypeEncryptedExtensions, &el)
				Expect(err).ToNot(HaveOccurred())
				close(done)
			}()
			Consistently(done).ShouldNot(BeClosed())
			Expect(handler.GetPeerParams()).To(Receive())
			Eventually(done).Should(BeClosed())
		})

		It("accepts the TransportParameters on the EncryptedExtensions message", func() {
			done := make(chan struct{})
			go func() {
				defer GinkgoRecover()
				addEncryptedExtensionsWithParameters(parameters)
				err := handler.Receive(mint.HandshakeTypeEncryptedExtensions, &el)
				Expect(err).ToNot(HaveOccurred())
				close(done)
			}()
			var params TransportParameters
			Eventually(handler.GetPeerParams()).Should(Receive(&params))
			Expect(params.IdleTimeout).To(Equal(0x1337 * time.Second))
			Eventually(done).Should(BeClosed())
		})

		It("errors if the EncryptedExtensions message doesn't contain TransportParameters", func() {
			err := handler.Receive(mint.HandshakeTypeEncryptedExtensions, &el)
			Expect(err).To(MatchError("EncryptedExtensions message didn't contain a QUIC extension"))
		})

		It("rejects the TransportParameters on a wrong handshake types", func() {
			err := el.Add(fakeBody)
			Expect(err).ToNot(HaveOccurred())
			err = handler.Receive(mint.HandshakeTypeCertificate, &el)
			Expect(err).To(MatchError(fmt.Sprintf("Unexpected QUIC extension in handshake message %d", mint.HandshakeTypeCertificate)))
		})

		It("ignores messages without TransportParameters, if they are not required", func() {
			err := handler.Receive(mint.HandshakeTypeCertificate, &el)
			Expect(err).ToNot(HaveOccurred())
		})

		It("errors when it can't parse the TransportParameters", func() {
			err := el.Add(fakeBody)
			Expect(err).ToNot(HaveOccurred())
			err = handler.Receive(mint.HandshakeTypeEncryptedExtensions, &el)
			Expect(err).To(HaveOccurred()) // this will be some kind of decoding error
		})

		It("rejects TransportParameters if they don't contain the stateless reset token", func() {
			parameters.StatelessResetToken = nil
			addEncryptedExtensionsWithParameters(parameters)
			err := handler.Receive(mint.HandshakeTypeEncryptedExtensions, &el)
			Expect(err).To(MatchError("server didn't sent stateless_reset_token"))
		})

		Context("Version Negotiation", func() {
			It("accepts a valid version negotiation", func() {
				done := make(chan struct{})
				go func() {
					defer GinkgoRecover()
					Eventually(handler.GetPeerParams()).Should(Receive())
					close(done)
				}()

				handler.initialVersion = 13
				handler.version = 37
				handler.supportedVersions = []protocol.VersionNumber{13, 37, 42}
				body := (&encryptedExtensionsTransportParameters{
					Parameters:        parameters,
					NegotiatedVersion: 37,
					SupportedVersions: []protocol.VersionNumber{36, 37, 38},
				}).Marshal()
				err := el.Add(&tlsExtensionBody{data: body})
				Expect(err).ToNot(HaveOccurred())
				err = handler.Receive(mint.HandshakeTypeEncryptedExtensions, &el)
				Expect(err).ToNot(HaveOccurred())
				Eventually(done).Should(BeClosed())
			})

			It("errors if the current version doesn't match negotiated_version", func() {
				handler.initialVersion = 13
				handler.version = 37
				handler.supportedVersions = []protocol.VersionNumber{13, 37, 42}
				body := (&encryptedExtensionsTransportParameters{
					Parameters:        parameters,
					NegotiatedVersion: 38,
					SupportedVersions: []protocol.VersionNumber{36, 37, 38},
				}).Marshal()
				err := el.Add(&tlsExtensionBody{data: body})
				Expect(err).ToNot(HaveOccurred())
				err = handler.Receive(mint.HandshakeTypeEncryptedExtensions, &el)
				Expect(err).To(MatchError("VersionNegotiationMismatch: current version doesn't match negotiated_version"))
			})

			It("errors if the current version is not contained in the server's supported versions", func() {
				handler.version = 42
				body := (&encryptedExtensionsTransportParameters{
					NegotiatedVersion: 42,
					SupportedVersions: []protocol.VersionNumber{43, 44},
				}).Marshal()
				err := el.Add(&tlsExtensionBody{data: body})
				Expect(err).ToNot(HaveOccurred())
				err = handler.Receive(mint.HandshakeTypeEncryptedExtensions, &el)
				Expect(err).To(MatchError("VersionNegotiationMismatch: current version not included in the supported versions"))
			})

			It("errors if version negotiation was performed, but would have picked a different version based on the supported version list", func() {
				handler.version = 42
				handler.initialVersion = 41
				handler.supportedVersions = []protocol.VersionNumber{43, 42, 41}
				serverSupportedVersions := []protocol.VersionNumber{42, 43}
				// check that version negotiation would have led us to pick version 43
				ver, ok := protocol.ChooseSupportedVersion(handler.supportedVersions, serverSupportedVersions)
				Expect(ok).To(BeTrue())
				Expect(ver).To(Equal(protocol.VersionNumber(43)))
				body := (&encryptedExtensionsTransportParameters{
					NegotiatedVersion: 42,
					SupportedVersions: serverSupportedVersions,
				}).Marshal()
				err := el.Add(&tlsExtensionBody{data: body})
				Expect(err).ToNot(HaveOccurred())
				err = handler.Receive(mint.HandshakeTypeEncryptedExtensions, &el)
				Expect(err).To(MatchError("VersionNegotiationMismatch: would have picked a different version"))
			})

			It("doesn't error if it would have picked a different version based on the supported version list, if no version negotiation was performed", func() {
				done := make(chan struct{})
				go func() {
					defer GinkgoRecover()
					Eventually(handler.GetPeerParams()).Should(Receive())
					close(done)
				}()

				handler.version = 42
				handler.initialVersion = 42 // version == initialVersion means no version negotiation was performed
				handler.supportedVersions = []protocol.VersionNumber{43, 42, 41}
				serverSupportedVersions := []protocol.VersionNumber{42, 43}
				// check that version negotiation would have led us to pick version 43
				ver, ok := protocol.ChooseSupportedVersion(handler.supportedVersions, serverSupportedVersions)
				Expect(ok).To(BeTrue())
				Expect(ver).To(Equal(protocol.VersionNumber(43)))
				body := (&encryptedExtensionsTransportParameters{
					Parameters:        parameters,
					NegotiatedVersion: 42,
					SupportedVersions: serverSupportedVersions,
				}).Marshal()
				err := el.Add(&tlsExtensionBody{data: body})
				Expect(err).ToNot(HaveOccurred())
				err = handler.Receive(mint.HandshakeTypeEncryptedExtensions, &el)
				Expect(err).ToNot(HaveOccurred())
				Eventually(done).Should(BeClosed())
			})
		})
	})
})
