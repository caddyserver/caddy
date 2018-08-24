package quic

import (
	"bytes"
	"crypto/tls"
	"errors"
	"net"
	"reflect"
	"time"

	"github.com/golang/mock/gomock"
	"github.com/lucas-clemente/quic-go/internal/handshake"
	"github.com/lucas-clemente/quic-go/internal/protocol"
	"github.com/lucas-clemente/quic-go/internal/testdata"
	"github.com/lucas-clemente/quic-go/internal/utils"
	"github.com/lucas-clemente/quic-go/internal/wire"

	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"
)

type mockSession struct {
	*MockQuicSession

	connID protocol.ConnectionID
	runner sessionRunner
}

func (s *mockSession) GetPerspective() protocol.Perspective { panic("not implemented") }

var _ = Describe("Server", func() {
	var (
		conn    *mockPacketConn
		config  *Config
		udpAddr = &net.UDPAddr{IP: net.IPv4(192, 168, 100, 200), Port: 1337}
	)

	BeforeEach(func() {
		conn = newMockPacketConn()
		conn.addr = &net.UDPAddr{}
		config = &Config{Versions: protocol.SupportedVersions}
	})

	Context("quic.Config", func() {
		It("setups with the right values", func() {
			config := &Config{
				HandshakeTimeout:            1337 * time.Minute,
				IdleTimeout:                 42 * time.Hour,
				RequestConnectionIDOmission: true,
				MaxIncomingStreams:          1234,
				MaxIncomingUniStreams:       4321,
				ConnectionIDLength:          12,
			}
			c := populateServerConfig(config)
			Expect(c.HandshakeTimeout).To(Equal(1337 * time.Minute))
			Expect(c.IdleTimeout).To(Equal(42 * time.Hour))
			Expect(c.RequestConnectionIDOmission).To(BeFalse())
			Expect(c.MaxIncomingStreams).To(Equal(1234))
			Expect(c.MaxIncomingUniStreams).To(Equal(4321))
			Expect(c.ConnectionIDLength).To(Equal(12))
		})

		It("disables bidirectional streams", func() {
			config := &Config{
				MaxIncomingStreams:    -1,
				MaxIncomingUniStreams: 4321,
			}
			c := populateServerConfig(config)
			Expect(c.MaxIncomingStreams).To(BeZero())
			Expect(c.MaxIncomingUniStreams).To(Equal(4321))
		})

		It("disables unidirectional streams", func() {
			config := &Config{
				MaxIncomingStreams:    1234,
				MaxIncomingUniStreams: -1,
			}
			c := populateServerConfig(config)
			Expect(c.MaxIncomingStreams).To(Equal(1234))
			Expect(c.MaxIncomingUniStreams).To(BeZero())
		})

		It("doesn't use 0-byte connection IDs", func() {
			config := &Config{}
			c := populateServerConfig(config)
			Expect(c.ConnectionIDLength).To(Equal(protocol.DefaultConnectionIDLength))
		})
	})

	Context("with mock session", func() {
		var (
			serv           *server
			firstPacket    *receivedPacket
			connID         = protocol.ConnectionID{0x4c, 0xfa, 0x9f, 0x9b, 0x66, 0x86, 0x19, 0xf6}
			sessions       = make([]*MockQuicSession, 0)
			sessionHandler *MockPacketHandlerManager
		)

		BeforeEach(func() {
			sessionHandler = NewMockPacketHandlerManager(mockCtrl)
			newMockSession := func(
				_ connection,
				runner sessionRunner,
				_ protocol.VersionNumber,
				connID protocol.ConnectionID,
				_ *handshake.ServerConfig,
				_ *tls.Config,
				_ *Config,
				_ utils.Logger,
			) (quicSession, error) {
				ExpectWithOffset(0, sessions).ToNot(BeEmpty())
				s := &mockSession{MockQuicSession: sessions[0]}
				s.connID = connID
				s.runner = runner
				sessions = sessions[1:]
				return s, nil
			}
			serv = &server{
				sessionHandler: sessionHandler,
				newSession:     newMockSession,
				conn:           conn,
				config:         config,
				sessionQueue:   make(chan Session, 5),
				errorChan:      make(chan struct{}),
				logger:         utils.DefaultLogger,
			}
			serv.setup()
			b := &bytes.Buffer{}
			utils.BigEndian.WriteUint32(b, uint32(protocol.SupportedVersions[0]))
			firstPacket = &receivedPacket{
				header: &wire.Header{
					VersionFlag:      true,
					Version:          serv.config.Versions[0],
					DestConnectionID: protocol.ConnectionID{0x4c, 0xfa, 0x9f, 0x9b, 0x66, 0x86, 0x19, 0xf6},
					PacketNumber:     1,
				},
				data:    bytes.Repeat([]byte{0}, protocol.MinClientHelloSize),
				rcvTime: time.Now(),
			}
		})

		AfterEach(func() {
			Expect(sessions).To(BeEmpty())
		})

		It("returns the address", func() {
			conn.addr = &net.UDPAddr{
				IP:   net.IPv4(192, 168, 13, 37),
				Port: 1234,
			}
			Expect(serv.Addr().String()).To(Equal("192.168.13.37:1234"))
		})

		It("creates new sessions", func() {
			s := NewMockQuicSession(mockCtrl)
			s.EXPECT().handlePacket(gomock.Any())
			run := make(chan struct{})
			s.EXPECT().run().Do(func() { close(run) })
			sessions = append(sessions, s)

			sessionHandler.EXPECT().Add(connID, gomock.Any()).Do(func(cid protocol.ConnectionID, _ packetHandler) {
				Expect(cid).To(Equal(connID))
			})
			Expect(serv.handlePacketImpl(firstPacket)).To(Succeed())
			Eventually(run).Should(BeClosed())
		})

		It("accepts new TLS sessions", func() {
			connID := protocol.ConnectionID{1, 2, 3, 4, 5, 6, 7, 8}
			sess := NewMockQuicSession(mockCtrl)
			err := serv.setupTLS()
			Expect(err).ToNot(HaveOccurred())
			added := make(chan struct{})
			sessionHandler.EXPECT().Add(connID, gomock.Any()).Do(func(_ protocol.ConnectionID, ph packetHandler) {
				Expect(ph.GetPerspective()).To(Equal(protocol.PerspectiveServer))
				close(added)
			})
			serv.serverTLS.sessionChan <- tlsSession{
				connID: connID,
				sess:   sess,
			}
			Eventually(added).Should(BeClosed())
		})

		It("accepts a session once the connection it is forward secure", func() {
			s := NewMockQuicSession(mockCtrl)
			s.EXPECT().handlePacket(gomock.Any())
			run := make(chan struct{})
			s.EXPECT().run().Do(func() { close(run) })
			sessions = append(sessions, s)
			done := make(chan struct{})
			go func() {
				defer GinkgoRecover()
				_, err := serv.Accept()
				Expect(err).ToNot(HaveOccurred())
				close(done)
			}()
			sessionHandler.EXPECT().Add(connID, gomock.Any()).Do(func(_ protocol.ConnectionID, sess packetHandler) {
				Consistently(done).ShouldNot(BeClosed())
				sess.(*serverSession).quicSession.(*mockSession).runner.onHandshakeComplete(sess.(Session))
			})
			err := serv.handlePacketImpl(firstPacket)
			Expect(err).ToNot(HaveOccurred())
			Eventually(done).Should(BeClosed())
			Eventually(run).Should(BeClosed())
		})

		It("doesn't accept sessions that error during the handshake", func() {
			run := make(chan error, 1)
			sess := NewMockQuicSession(mockCtrl)
			sess.EXPECT().handlePacket(gomock.Any())
			sess.EXPECT().run().DoAndReturn(func() error { return <-run })
			sessions = append(sessions, sess)
			done := make(chan struct{})
			go func() {
				defer GinkgoRecover()
				serv.Accept()
				close(done)
			}()
			sessionHandler.EXPECT().Add(connID, gomock.Any()).Do(func(protocol.ConnectionID, packetHandler) {
				run <- errors.New("handshake error")
			})
			Expect(serv.handlePacketImpl(firstPacket)).To(Succeed())
			Consistently(done).ShouldNot(BeClosed())

			// make the go routine return
			close(serv.errorChan)
			Eventually(done).Should(BeClosed())
		})

		It("closes the sessionHandler when Close is called", func() {
			sessionHandler.EXPECT().CloseServer()
			Expect(serv.Close()).To(Succeed())
		})

		It("works if no quic.Config is given", func(done Done) {
			ln, err := ListenAddr("127.0.0.1:0", testdata.GetTLSConfig(), nil)
			Expect(err).ToNot(HaveOccurred())
			Expect(ln.Close()).To(Succeed())
			close(done)
		}, 1)

		It("closes properly", func() {
			ln, err := ListenAddr("127.0.0.1:0", testdata.GetTLSConfig(), config)
			Expect(err).ToNot(HaveOccurred())

			done := make(chan struct{})
			go func() {
				defer GinkgoRecover()
				ln.Accept()
				close(done)
			}()
			ln.Close()
			Eventually(done).Should(BeClosed())
		})

		It("closes the connection when it was created with ListenAddr", func() {
			addr, err := net.ResolveUDPAddr("udp", "localhost:12345")
			Expect(err).ToNot(HaveOccurred())

			serv, err := ListenAddr("localhost:0", nil, nil)
			Expect(err).ToNot(HaveOccurred())
			// test that we can write on the packet conn
			_, err = serv.(*server).conn.WriteTo([]byte("foobar"), addr)
			Expect(err).ToNot(HaveOccurred())
			Expect(serv.Close()).To(Succeed())
			// test that we can't write any more on the packet conn
			_, err = serv.(*server).conn.WriteTo([]byte("foobar"), addr)
			Expect(err.Error()).To(ContainSubstring("use of closed network connection"))
		})

		It("returns Accept when it is closed", func() {
			done := make(chan struct{})
			go func() {
				defer GinkgoRecover()
				_, err := serv.Accept()
				Expect(err).To(MatchError("server closed"))
				close(done)
			}()
			sessionHandler.EXPECT().CloseServer()
			Expect(serv.Close()).To(Succeed())
			Eventually(done).Should(BeClosed())
		})

		It("returns Accept with the right error when closeWithError is called", func() {
			testErr := errors.New("connection error")
			done := make(chan struct{})
			go func() {
				defer GinkgoRecover()
				_, err := serv.Accept()
				Expect(err).To(MatchError(testErr))
				close(done)
			}()
			sessionHandler.EXPECT().CloseServer()
			serv.closeWithError(testErr)
			Eventually(done).Should(BeClosed())
		})

		It("doesn't try to process a packet after sending a gQUIC Version Negotiation Packet", func() {
			config.Versions = []protocol.VersionNumber{99}
			p := &receivedPacket{
				header: &wire.Header{
					VersionFlag:      true,
					DestConnectionID: connID,
					PacketNumber:     1,
					PacketNumberLen:  protocol.PacketNumberLen2,
				},
				data: make([]byte, protocol.MinClientHelloSize),
			}
			Expect(serv.handlePacketImpl(p)).To(Succeed())
			Expect(conn.dataWritten.Bytes()).ToNot(BeEmpty())
		})

		It("sends a PUBLIC_RESET for new connections that don't have the VersionFlag set", func() {
			err := serv.handlePacketImpl(&receivedPacket{
				remoteAddr: udpAddr,
				header: &wire.Header{
					IsPublicHeader: true,
				},
			})
			Expect(err).ToNot(HaveOccurred())

			Expect(conn.dataWritten.Len()).ToNot(BeZero())
			Expect(conn.dataWrittenTo).To(Equal(udpAddr))
			Expect(conn.dataWritten.Bytes()[0] & 0x02).ToNot(BeZero()) // check that the ResetFlag is set
		})

		It("sends a gQUIC Version Negotaion Packet, if the client sent a gQUIC Public Header", func() {
			connID := protocol.ConnectionID{8, 7, 6, 5, 4, 3, 2, 1}
			err := serv.handlePacketImpl(&receivedPacket{
				remoteAddr: udpAddr,
				header: &wire.Header{
					VersionFlag:      true,
					DestConnectionID: connID,
					PacketNumber:     1,
					PacketNumberLen:  protocol.PacketNumberLen2,
					Version:          protocol.Version39 - 1,
				},
			})
			Expect(err).ToNot(HaveOccurred())

			Expect(conn.dataWritten.Len()).ToNot(BeZero())
			Expect(conn.dataWrittenTo).To(Equal(udpAddr))
			r := bytes.NewReader(conn.dataWritten.Bytes())
			iHdr, err := wire.ParseInvariantHeader(r, 0)
			Expect(err).ToNot(HaveOccurred())
			Expect(iHdr.IsLongHeader).To(BeFalse())
			replyHdr, err := iHdr.Parse(r, protocol.PerspectiveServer, versionIETFFrames)
			Expect(err).ToNot(HaveOccurred())
			Expect(replyHdr.IsVersionNegotiation).To(BeTrue())
			Expect(replyHdr.DestConnectionID).To(Equal(connID))
			Expect(r.Len()).To(BeZero())
		})

		It("sends an IETF draft style Version Negotaion Packet, if the client sent a IETF draft style header", func() {
			connID := protocol.ConnectionID{8, 7, 6, 5, 4, 3, 2, 1}
			err := serv.handlePacketImpl(&receivedPacket{
				remoteAddr: udpAddr,
				header: &wire.Header{
					Type:             protocol.PacketTypeInitial,
					IsLongHeader:     true,
					DestConnectionID: connID,
					SrcConnectionID:  connID,
					PacketNumber:     0x55,
					PacketNumberLen:  protocol.PacketNumberLen1,
					Version:          0x1234,
					PayloadLen:       protocol.MinInitialPacketSize,
				},
			})
			Expect(err).ToNot(HaveOccurred())

			Expect(conn.dataWritten.Len()).ToNot(BeZero())
			Expect(conn.dataWrittenTo).To(Equal(udpAddr))
			r := bytes.NewReader(conn.dataWritten.Bytes())
			iHdr, err := wire.ParseInvariantHeader(r, 0)
			Expect(err).ToNot(HaveOccurred())
			replyHdr, err := iHdr.Parse(r, protocol.PerspectiveServer, versionIETFFrames)
			Expect(err).ToNot(HaveOccurred())
			Expect(replyHdr.IsVersionNegotiation).To(BeTrue())
			Expect(replyHdr.DestConnectionID).To(Equal(connID))
			Expect(replyHdr.SrcConnectionID).To(Equal(connID))
			Expect(r.Len()).To(BeZero())
		})
	})

	It("setups with the right values", func() {
		supportedVersions := []protocol.VersionNumber{protocol.VersionTLS, protocol.Version39}
		acceptCookie := func(_ net.Addr, _ *Cookie) bool { return true }
		config := Config{
			Versions:         supportedVersions,
			AcceptCookie:     acceptCookie,
			HandshakeTimeout: 1337 * time.Hour,
			IdleTimeout:      42 * time.Minute,
			KeepAlive:        true,
		}
		ln, err := Listen(conn, &tls.Config{}, &config)
		Expect(err).ToNot(HaveOccurred())
		server := ln.(*server)
		Expect(server.sessionHandler).ToNot(BeNil())
		Expect(server.scfg).ToNot(BeNil())
		Expect(server.config.Versions).To(Equal(supportedVersions))
		Expect(server.config.HandshakeTimeout).To(Equal(1337 * time.Hour))
		Expect(server.config.IdleTimeout).To(Equal(42 * time.Minute))
		Expect(reflect.ValueOf(server.config.AcceptCookie)).To(Equal(reflect.ValueOf(acceptCookie)))
		Expect(server.config.KeepAlive).To(BeTrue())
	})

	It("errors when the Config contains an invalid version", func() {
		version := protocol.VersionNumber(0x1234)
		_, err := Listen(conn, &tls.Config{}, &Config{Versions: []protocol.VersionNumber{version}})
		Expect(err).To(MatchError("0x1234 is not a valid QUIC version"))
	})

	It("fills in default values if options are not set in the Config", func() {
		ln, err := Listen(conn, &tls.Config{}, &Config{})
		Expect(err).ToNot(HaveOccurred())
		server := ln.(*server)
		Expect(server.config.Versions).To(Equal(protocol.SupportedVersions))
		Expect(server.config.HandshakeTimeout).To(Equal(protocol.DefaultHandshakeTimeout))
		Expect(server.config.IdleTimeout).To(Equal(protocol.DefaultIdleTimeout))
		Expect(reflect.ValueOf(server.config.AcceptCookie)).To(Equal(reflect.ValueOf(defaultAcceptCookie)))
		Expect(server.config.KeepAlive).To(BeFalse())
	})

	It("listens on a given address", func() {
		addr := "127.0.0.1:13579"
		ln, err := ListenAddr(addr, nil, config)
		Expect(err).ToNot(HaveOccurred())
		serv := ln.(*server)
		Expect(serv.Addr().String()).To(Equal(addr))
	})

	It("errors if given an invalid address", func() {
		addr := "127.0.0.1"
		_, err := ListenAddr(addr, nil, config)
		Expect(err).To(BeAssignableToTypeOf(&net.AddrError{}))
	})

	It("errors if given an invalid address", func() {
		addr := "1.1.1.1:1111"
		_, err := ListenAddr(addr, nil, config)
		Expect(err).To(BeAssignableToTypeOf(&net.OpError{}))
	})
})

var _ = Describe("default source address verification", func() {
	It("accepts a token", func() {
		remoteAddr := &net.UDPAddr{IP: net.IPv4(192, 168, 0, 1)}
		cookie := &Cookie{
			RemoteAddr: "192.168.0.1",
			SentTime:   time.Now().Add(-protocol.CookieExpiryTime).Add(time.Second), // will expire in 1 second
		}
		Expect(defaultAcceptCookie(remoteAddr, cookie)).To(BeTrue())
	})

	It("requests verification if no token is provided", func() {
		remoteAddr := &net.UDPAddr{IP: net.IPv4(192, 168, 0, 1)}
		Expect(defaultAcceptCookie(remoteAddr, nil)).To(BeFalse())
	})

	It("rejects a token if the address doesn't match", func() {
		remoteAddr := &net.UDPAddr{IP: net.IPv4(192, 168, 0, 1)}
		cookie := &Cookie{
			RemoteAddr: "127.0.0.1",
			SentTime:   time.Now(),
		}
		Expect(defaultAcceptCookie(remoteAddr, cookie)).To(BeFalse())
	})

	It("accepts a token for a remote address is not a UDP address", func() {
		remoteAddr := &net.TCPAddr{IP: net.IPv4(192, 168, 0, 1), Port: 1337}
		cookie := &Cookie{
			RemoteAddr: "192.168.0.1:1337",
			SentTime:   time.Now(),
		}
		Expect(defaultAcceptCookie(remoteAddr, cookie)).To(BeTrue())
	})

	It("rejects an invalid token for a remote address is not a UDP address", func() {
		remoteAddr := &net.TCPAddr{IP: net.IPv4(192, 168, 0, 1), Port: 1337}
		cookie := &Cookie{
			RemoteAddr: "192.168.0.1:7331", // mismatching port
			SentTime:   time.Now(),
		}
		Expect(defaultAcceptCookie(remoteAddr, cookie)).To(BeFalse())
	})

	It("rejects an expired token", func() {
		remoteAddr := &net.UDPAddr{IP: net.IPv4(192, 168, 0, 1)}
		cookie := &Cookie{
			RemoteAddr: "192.168.0.1",
			SentTime:   time.Now().Add(-protocol.CookieExpiryTime).Add(-time.Second), // expired 1 second ago
		}
		Expect(defaultAcceptCookie(remoteAddr, cookie)).To(BeFalse())
	})
})
