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

var _ = Describe("TLS Extension Handler, for the server", func() {
	var (
		handler *extensionHandlerServer
		el      mint.ExtensionList
	)

	BeforeEach(func() {
		handler = NewExtensionHandlerServer(&TransportParameters{}, nil, protocol.VersionWhatever, utils.DefaultLogger).(*extensionHandlerServer)
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

		It("adds TransportParameters to the EncryptedExtensions message", func() {
			handler.version = 666
			versions := []protocol.VersionNumber{13, 37, 42}
			handler.supportedVersions = versions
			err := handler.Send(mint.HandshakeTypeEncryptedExtensions, &el)
			Expect(err).ToNot(HaveOccurred())
			Expect(el).To(HaveLen(1))
			ext := &tlsExtensionBody{}
			found, err := el.Find(ext)
			Expect(err).ToNot(HaveOccurred())
			Expect(found).To(BeTrue())
			eetp := &encryptedExtensionsTransportParameters{}
			err = eetp.Unmarshal(ext.data)
			Expect(err).ToNot(HaveOccurred())
			Expect(eetp.NegotiatedVersion).To(BeEquivalentTo(666))
			// the SupportedVersions will contain one reserved version number
			Expect(eetp.SupportedVersions).To(HaveLen(len(versions) + 1))
			for _, version := range versions {
				Expect(eetp.SupportedVersions).To(ContainElement(version))
			}
		})
	})

	Context("receiving", func() {
		var (
			fakeBody   *tlsExtensionBody
			parameters TransportParameters
		)

		addClientHelloWithParameters := func(params TransportParameters) {
			body := (&clientHelloTransportParameters{Parameters: params}).Marshal()
			Expect(el.Add(&tlsExtensionBody{data: body})).To(Succeed())
		}

		BeforeEach(func() {
			fakeBody = &tlsExtensionBody{data: []byte("foobar foobar")}
			parameters = TransportParameters{IdleTimeout: 0x1337 * time.Second}
		})

		It("accepts the TransportParameters on the EncryptedExtensions message", func() {
			addClientHelloWithParameters(parameters)
			err := handler.Receive(mint.HandshakeTypeClientHello, &el)
			Expect(err).ToNot(HaveOccurred())
			var params TransportParameters
			Expect(handler.GetPeerParams()).To(Receive(&params))
			Expect(params.IdleTimeout).To(Equal(0x1337 * time.Second))
		})

		It("errors if the ClientHello doesn't contain TransportParameters", func() {
			err := handler.Receive(mint.HandshakeTypeClientHello, &el)
			Expect(err).To(MatchError("ClientHello didn't contain a QUIC extension"))
		})

		It("ignores messages without TransportParameters, if they are not required", func() {
			err := handler.Receive(mint.HandshakeTypeCertificate, &el)
			Expect(err).ToNot(HaveOccurred())
		})

		It("errors if it can't unmarshal the TransportParameters", func() {
			err := el.Add(fakeBody)
			Expect(err).ToNot(HaveOccurred())
			err = handler.Receive(mint.HandshakeTypeClientHello, &el)
			Expect(err).To(HaveOccurred()) // this will be some kind of decoding error
		})

		It("rejects messages other than the ClientHello that contain TransportParameters", func() {
			addClientHelloWithParameters(parameters)
			err := handler.Receive(mint.HandshakeTypeCertificateRequest, &el)
			Expect(err).To(MatchError(fmt.Sprintf("Unexpected QUIC extension in handshake message %d", mint.HandshakeTypeCertificateRequest)))
		})

		It("rejects messages that contain a stateless reset token", func() {
			parameters.StatelessResetToken = bytes.Repeat([]byte{0}, 16)
			addClientHelloWithParameters(parameters)
			err := handler.Receive(mint.HandshakeTypeClientHello, &el)
			Expect(err).To(MatchError("client sent a stateless reset token"))
		})

		Context("Version Negotiation", func() {
			It("accepts a ClientHello, when no version negotiation was performed", func() {
				handler.version = 42
				body := (&clientHelloTransportParameters{
					InitialVersion: 42,
					Parameters:     parameters,
				}).Marshal()
				err := el.Add(&tlsExtensionBody{data: body})
				Expect(err).ToNot(HaveOccurred())
				err = handler.Receive(mint.HandshakeTypeClientHello, &el)
				Expect(err).ToNot(HaveOccurred())
			})

			It("accepts a valid version negotiation", func() {
				handler.version = 42
				handler.supportedVersions = []protocol.VersionNumber{13, 37, 42}
				body := (&clientHelloTransportParameters{
					InitialVersion: 22, // this must be an unsupported version
					Parameters:     parameters,
				}).Marshal()
				err := el.Add(&tlsExtensionBody{data: body})
				Expect(err).ToNot(HaveOccurred())
				err = handler.Receive(mint.HandshakeTypeClientHello, &el)
				Expect(err).ToNot(HaveOccurred())
			})

			It("erros when a version negotiation was performed, although we already support the initial version", func() {
				handler.supportedVersions = []protocol.VersionNumber{11, 12, 13}
				handler.version = 13
				body := (&clientHelloTransportParameters{
					InitialVersion: 11, // this is an supported version
				}).Marshal()
				err := el.Add(&tlsExtensionBody{data: body})
				Expect(err).ToNot(HaveOccurred())
				err = handler.Receive(mint.HandshakeTypeClientHello, &el)
				Expect(err).To(MatchError("VersionNegotiationMismatch: Client should have used the initial version"))
			})
		})
	})
})
