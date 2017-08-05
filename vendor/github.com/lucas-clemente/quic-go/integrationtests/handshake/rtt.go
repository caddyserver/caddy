package handshaketests

import (
	"crypto/tls"
	"fmt"
	"net"
	"time"

	quic "github.com/lucas-clemente/quic-go"
	"github.com/lucas-clemente/quic-go/integrationtests/proxy"
	"github.com/lucas-clemente/quic-go/internal/utils"
	"github.com/lucas-clemente/quic-go/protocol"
	"github.com/lucas-clemente/quic-go/qerr"

	"github.com/lucas-clemente/quic-go/testdata"
	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"
)

var _ = Describe("Handshake integration tets", func() {
	var (
		proxy         *quicproxy.QuicProxy
		server        quic.Listener
		serverConfig  *quic.Config
		testStartedAt time.Time
	)
	rtt := 400 * time.Millisecond

	BeforeEach(func() {
		serverConfig = &quic.Config{}
	})

	AfterEach(func() {
		Expect(proxy.Close()).To(Succeed())
		Expect(server.Close()).To(Succeed())
	})

	runServerAndProxy := func() {
		var err error
		// start the server
		server, err = quic.ListenAddr("localhost:0", testdata.GetTLSConfig(), serverConfig)
		Expect(err).ToNot(HaveOccurred())
		// start the proxy
		proxy, err = quicproxy.NewQuicProxy("localhost:0", quicproxy.Opts{
			RemoteAddr:  server.Addr().String(),
			DelayPacket: func(_ quicproxy.Direction, _ protocol.PacketNumber) time.Duration { return rtt / 2 },
		})
		Expect(err).ToNot(HaveOccurred())

		testStartedAt = time.Now()

		go func() {
			for {
				_, _ = server.Accept()
			}
		}()
	}

	expectDurationInRTTs := func(num int) {
		testDuration := time.Since(testStartedAt)
		expectedDuration := time.Duration(num) * rtt
		Expect(testDuration).To(SatisfyAll(
			BeNumerically(">=", expectedDuration),
			BeNumerically("<", expectedDuration+rtt),
		))
	}

	It("fails when there's no matching version, after 1 RTT", func() {
		Expect(len(protocol.SupportedVersions)).To(BeNumerically(">", 1))
		serverConfig.Versions = protocol.SupportedVersions[:1]
		runServerAndProxy()
		clientConfig := &quic.Config{
			Versions: protocol.SupportedVersions[1:2],
		}
		_, err := quic.DialAddr(proxy.LocalAddr().String(), nil, clientConfig)
		Expect(err).To(HaveOccurred())
		Expect(err.(qerr.ErrorCode)).To(Equal(qerr.InvalidVersion))
		expectDurationInRTTs(1)
	})

	// 1 RTT for verifying the source address
	// 1 RTT to become secure
	// 1 RTT to become forward-secure
	It("is forward-secure after 3 RTTs", func() {
		runServerAndProxy()
		_, err := quic.DialAddr(proxy.LocalAddr().String(), &tls.Config{InsecureSkipVerify: true}, nil)
		Expect(err).ToNot(HaveOccurred())
		expectDurationInRTTs(3)
	})

	// 1 RTT for verifying the source address
	// 1 RTT to become secure
	// TODO (marten-seemann): enable this test (see #625)
	PIt("is secure after 2 RTTs", func() {
		utils.SetLogLevel(utils.LogLevelDebug)
		runServerAndProxy()
		_, err := quic.DialAddrNonFWSecure(proxy.LocalAddr().String(), &tls.Config{InsecureSkipVerify: true}, nil)
		fmt.Println("#### is non fw secure ###")
		Expect(err).ToNot(HaveOccurred())
		expectDurationInRTTs(2)
	})

	It("is forward-secure after 2 RTTs when the server doesn't require an STK", func() {
		serverConfig.AcceptSTK = func(_ net.Addr, _ *quic.STK) bool {
			return true
		}
		runServerAndProxy()
		_, err := quic.DialAddr(proxy.LocalAddr().String(), &tls.Config{InsecureSkipVerify: true}, nil)
		Expect(err).ToNot(HaveOccurred())
		expectDurationInRTTs(2)
	})

	It("doesn't complete the handshake when the server never accepts the STK", func() {
		serverConfig.AcceptSTK = func(_ net.Addr, _ *quic.STK) bool {
			return false
		}
		runServerAndProxy()
		_, err := quic.DialAddr(proxy.LocalAddr().String(), &tls.Config{InsecureSkipVerify: true}, nil)
		Expect(err).To(HaveOccurred())
		Expect(err.(*qerr.QuicError).ErrorCode).To(Equal(qerr.CryptoTooManyRejects))
	})

	It("doesn't complete the handshake when the handshake timeout is too short", func() {
		serverConfig.HandshakeTimeout = 2 * rtt
		runServerAndProxy()
		_, err := quic.DialAddr(proxy.LocalAddr().String(), &tls.Config{InsecureSkipVerify: true}, nil)
		Expect(err).To(HaveOccurred())
		Expect(err.(*qerr.QuicError).ErrorCode).To(Equal(qerr.HandshakeTimeout))
		// 2 RTTs during the timeout
		// plus 1 RTT: the timer starts 0.5 RTTs after sending the first packet, and the CONNECTION_CLOSE needs another 0.5 RTTs to reach the client
		expectDurationInRTTs(3)
	})
})
