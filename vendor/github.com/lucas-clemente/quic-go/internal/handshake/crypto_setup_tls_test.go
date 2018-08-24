package handshake

import (
	"bytes"
	"errors"
	"fmt"

	"github.com/bifurcation/mint"
	"github.com/lucas-clemente/quic-go/internal/crypto"
	"github.com/lucas-clemente/quic-go/internal/mocks/crypto"
	"github.com/lucas-clemente/quic-go/internal/protocol"

	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"
)

func mockKeyDerivation(crypto.TLSExporter, protocol.Perspective) (crypto.AEAD, error) {
	return mockcrypto.NewMockAEAD(mockCtrl), nil
}

var _ = Describe("TLS Crypto Setup", func() {
	var (
		cs             *cryptoSetupTLS
		handshakeEvent chan struct{}
	)

	BeforeEach(func() {
		handshakeEvent = make(chan struct{}, 2)
		css, err := NewCryptoSetupTLSServer(
			newCryptoStreamConn(bytes.NewBuffer([]byte{})),
			protocol.ConnectionID{},
			&mint.Config{},
			handshakeEvent,
			protocol.VersionTLS,
		)
		Expect(err).ToNot(HaveOccurred())
		cs = css.(*cryptoSetupTLS)
		cs.nullAEAD = mockcrypto.NewMockAEAD(mockCtrl)
	})

	It("errors when the handshake fails", func() {
		alert := mint.AlertBadRecordMAC
		cs.tls = NewMockMintTLS(mockCtrl)
		cs.tls.(*MockMintTLS).EXPECT().Handshake().Return(alert)
		err := cs.HandleCryptoStream()
		Expect(err).To(MatchError(fmt.Errorf("TLS handshake error: %s (Alert %d)", alert.String(), alert)))
	})

	It("derives keys", func() {
		cs.tls = NewMockMintTLS(mockCtrl)
		cs.tls.(*MockMintTLS).EXPECT().Handshake().Return(mint.AlertNoAlert)
		cs.tls.(*MockMintTLS).EXPECT().ConnectionState().Return(mint.ConnectionState{HandshakeState: mint.StateServerConnected})
		cs.keyDerivation = mockKeyDerivation
		err := cs.HandleCryptoStream()
		Expect(err).ToNot(HaveOccurred())
		Expect(handshakeEvent).To(Receive())
		Expect(handshakeEvent).To(BeClosed())
	})

	It("handshakes until it is connected", func() {
		cs.tls = NewMockMintTLS(mockCtrl)
		cs.tls.(*MockMintTLS).EXPECT().Handshake().Return(mint.AlertNoAlert).Times(10)
		cs.tls.(*MockMintTLS).EXPECT().ConnectionState().Return(mint.ConnectionState{HandshakeState: mint.StateServerNegotiated}).Times(9)
		cs.tls.(*MockMintTLS).EXPECT().ConnectionState().Return(mint.ConnectionState{HandshakeState: mint.StateServerConnected})
		cs.keyDerivation = mockKeyDerivation
		err := cs.HandleCryptoStream()
		Expect(err).ToNot(HaveOccurred())
		Expect(handshakeEvent).To(Receive())
	})

	Context("reporting the handshake state", func() {
		It("reports before the handshake compeletes", func() {
			cs.tls = NewMockMintTLS(mockCtrl)
			cs.tls.(*MockMintTLS).EXPECT().ConnectionState().Return(mint.ConnectionState{})
			state := cs.ConnectionState()
			Expect(state.HandshakeComplete).To(BeFalse())
			Expect(state.PeerCertificates).To(BeNil())
		})

		It("reports after the handshake completes", func() {
			cs.tls = NewMockMintTLS(mockCtrl)
			cs.tls.(*MockMintTLS).EXPECT().Handshake().Return(mint.AlertNoAlert)
			cs.tls.(*MockMintTLS).EXPECT().ConnectionState().Return(mint.ConnectionState{HandshakeState: mint.StateServerConnected}).Times(2)
			cs.keyDerivation = mockKeyDerivation
			err := cs.HandleCryptoStream()
			Expect(err).ToNot(HaveOccurred())
			state := cs.ConnectionState()
			Expect(state.HandshakeComplete).To(BeTrue())
			Expect(state.PeerCertificates).To(BeNil())
		})
	})

	Context("escalating crypto", func() {
		doHandshake := func() {
			cs.tls = NewMockMintTLS(mockCtrl)
			cs.tls.(*MockMintTLS).EXPECT().Handshake().Return(mint.AlertNoAlert)
			cs.tls.(*MockMintTLS).EXPECT().ConnectionState().Return(mint.ConnectionState{HandshakeState: mint.StateServerConnected})
			cs.keyDerivation = mockKeyDerivation
			err := cs.HandleCryptoStream()
			Expect(err).ToNot(HaveOccurred())
		}

		Context("null encryption", func() {
			It("is used initially", func() {
				cs.nullAEAD.(*mockcrypto.MockAEAD).EXPECT().Seal(nil, []byte("foobar"), protocol.PacketNumber(5), []byte{}).Return([]byte("foobar signed"))
				enc, sealer := cs.GetSealer()
				Expect(enc).To(Equal(protocol.EncryptionUnencrypted))
				d := sealer.Seal(nil, []byte("foobar"), 5, []byte{})
				Expect(d).To(Equal([]byte("foobar signed")))
			})

			It("is used for opening", func() {
				cs.nullAEAD.(*mockcrypto.MockAEAD).EXPECT().Open(nil, []byte("foobar enc"), protocol.PacketNumber(10), []byte{}).Return([]byte("foobar"), nil)
				d, err := cs.OpenHandshake(nil, []byte("foobar enc"), 10, []byte{})
				Expect(err).ToNot(HaveOccurred())
				Expect(d).To(Equal([]byte("foobar")))
			})

			It("is used for crypto stream", func() {
				cs.nullAEAD.(*mockcrypto.MockAEAD).EXPECT().Seal(nil, []byte("foobar"), protocol.PacketNumber(20), []byte{}).Return([]byte("foobar signed"))
				enc, sealer := cs.GetSealerForCryptoStream()
				Expect(enc).To(Equal(protocol.EncryptionUnencrypted))
				d := sealer.Seal(nil, []byte("foobar"), 20, []byte{})
				Expect(d).To(Equal([]byte("foobar signed")))
			})

			It("errors if the has the wrong hash", func() {
				cs.nullAEAD.(*mockcrypto.MockAEAD).EXPECT().Open(nil, []byte("foobar enc"), protocol.PacketNumber(10), []byte{}).Return(nil, errors.New("authentication failed"))
				_, err := cs.OpenHandshake(nil, []byte("foobar enc"), 10, []byte{})
				Expect(err).To(MatchError("authentication failed"))
			})
		})

		Context("forward-secure encryption", func() {
			It("is used for sealing after the handshake completes", func() {
				doHandshake()
				cs.aead.(*mockcrypto.MockAEAD).EXPECT().Seal(nil, []byte("foobar"), protocol.PacketNumber(5), []byte{}).Return([]byte("foobar forward sec"))
				enc, sealer := cs.GetSealer()
				Expect(enc).To(Equal(protocol.EncryptionForwardSecure))
				d := sealer.Seal(nil, []byte("foobar"), 5, []byte{})
				Expect(d).To(Equal([]byte("foobar forward sec")))
			})

			It("is used for opening", func() {
				doHandshake()
				cs.aead.(*mockcrypto.MockAEAD).EXPECT().Open(nil, []byte("encrypted"), protocol.PacketNumber(6), []byte{}).Return([]byte("decrypted"), nil)
				d, err := cs.Open1RTT(nil, []byte("encrypted"), 6, []byte{})
				Expect(err).ToNot(HaveOccurred())
				Expect(d).To(Equal([]byte("decrypted")))
			})
		})

		Context("forcing encryption levels", func() {
			It("forces null encryption", func() {
				doHandshake()
				cs.nullAEAD.(*mockcrypto.MockAEAD).EXPECT().Seal(nil, []byte("foobar"), protocol.PacketNumber(5), []byte{}).Return([]byte("foobar signed"))
				sealer, err := cs.GetSealerWithEncryptionLevel(protocol.EncryptionUnencrypted)
				Expect(err).ToNot(HaveOccurred())
				d := sealer.Seal(nil, []byte("foobar"), 5, []byte{})
				Expect(d).To(Equal([]byte("foobar signed")))
			})

			It("forces forward-secure encryption", func() {
				doHandshake()
				cs.aead.(*mockcrypto.MockAEAD).EXPECT().Seal(nil, []byte("foobar"), protocol.PacketNumber(5), []byte{}).Return([]byte("foobar forward sec"))
				sealer, err := cs.GetSealerWithEncryptionLevel(protocol.EncryptionForwardSecure)
				Expect(err).ToNot(HaveOccurred())
				d := sealer.Seal(nil, []byte("foobar"), 5, []byte{})
				Expect(d).To(Equal([]byte("foobar forward sec")))
			})

			It("errors if the forward-secure AEAD is not available", func() {
				sealer, err := cs.GetSealerWithEncryptionLevel(protocol.EncryptionForwardSecure)
				Expect(err).To(MatchError("CryptoSetup: no sealer with encryption level forward-secure"))
				Expect(sealer).To(BeNil())
			})

			It("never returns a secure AEAD (they don't exist with TLS)", func() {
				doHandshake()
				sealer, err := cs.GetSealerWithEncryptionLevel(protocol.EncryptionSecure)
				Expect(err).To(MatchError("CryptoSetup: no sealer with encryption level encrypted (not forward-secure)"))
				Expect(sealer).To(BeNil())
			})

			It("errors if no encryption level is specified", func() {
				seal, err := cs.GetSealerWithEncryptionLevel(protocol.EncryptionUnspecified)
				Expect(err).To(MatchError("CryptoSetup: no sealer with encryption level unknown"))
				Expect(seal).To(BeNil())
			})
		})
	})
})
