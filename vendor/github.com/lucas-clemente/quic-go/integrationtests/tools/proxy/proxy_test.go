package quicproxy

import (
	"bytes"
	"net"
	"runtime/pprof"
	"strconv"
	"strings"
	"sync/atomic"
	"time"

	"fmt"

	"github.com/lucas-clemente/quic-go/internal/protocol"
	"github.com/lucas-clemente/quic-go/internal/wire"
	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"
)

type packetData []byte

var _ = Describe("QUIC Proxy", func() {
	makePacket := func(p protocol.PacketNumber, payload []byte) []byte {
		b := &bytes.Buffer{}
		hdr := wire.Header{
			PacketNumber:     p,
			PacketNumberLen:  protocol.PacketNumberLen6,
			DestConnectionID: protocol.ConnectionID{0xde, 0xad, 0xbe, 0xef, 0, 0, 0x13, 0x37},
			SrcConnectionID:  protocol.ConnectionID{0xde, 0xad, 0xbe, 0xef, 0, 0, 0x13, 0x37},
		}
		hdr.Write(b, protocol.PerspectiveServer, protocol.VersionWhatever)
		raw := b.Bytes()
		raw = append(raw, payload...)
		return raw
	}

	Context("Proxy setup and teardown", func() {
		It("sets up the UDPProxy", func() {
			proxy, err := NewQuicProxy("localhost:0", protocol.VersionWhatever, nil)
			Expect(err).ToNot(HaveOccurred())
			Expect(proxy.clientDict).To(HaveLen(0))

			// check that the proxy port is in use
			addr, err := net.ResolveUDPAddr("udp", "localhost:"+strconv.Itoa(proxy.LocalPort()))
			Expect(err).ToNot(HaveOccurred())
			_, err = net.ListenUDP("udp", addr)
			Expect(err).To(MatchError(fmt.Sprintf("listen udp 127.0.0.1:%d: bind: address already in use", proxy.LocalPort())))
			Expect(proxy.Close()).To(Succeed()) // stopping is tested in the next test
		})

		It("stops the UDPProxy", func() {
			isProxyRunning := func() bool {
				var b bytes.Buffer
				pprof.Lookup("goroutine").WriteTo(&b, 1)
				return strings.Contains(b.String(), "proxy.(*QuicProxy).runProxy")
			}

			proxy, err := NewQuicProxy("localhost:0", protocol.VersionWhatever, nil)
			Expect(err).ToNot(HaveOccurred())
			port := proxy.LocalPort()
			Expect(isProxyRunning()).To(BeTrue())
			err = proxy.Close()
			Expect(err).ToNot(HaveOccurred())

			// check that the proxy port is not in use anymore
			addr, err := net.ResolveUDPAddr("udp", "localhost:"+strconv.Itoa(port))
			Expect(err).ToNot(HaveOccurred())
			// sometimes it takes a while for the OS to free the port
			Eventually(func() error {
				ln, err := net.ListenUDP("udp", addr)
				if err != nil {
					return err
				}
				ln.Close()
				return nil
			}).ShouldNot(HaveOccurred())
			Eventually(isProxyRunning).Should(BeFalse())
		})

		It("stops listening for proxied connections", func() {
			isConnRunning := func() bool {
				var b bytes.Buffer
				pprof.Lookup("goroutine").WriteTo(&b, 1)
				return strings.Contains(b.String(), "proxy.(*QuicProxy).runConnection")
			}

			serverAddr, err := net.ResolveUDPAddr("udp", "localhost:0")
			Expect(err).ToNot(HaveOccurred())
			serverConn, err := net.ListenUDP("udp", serverAddr)
			Expect(err).ToNot(HaveOccurred())
			defer serverConn.Close()

			proxy, err := NewQuicProxy("localhost:0", protocol.VersionWhatever, &Opts{RemoteAddr: serverConn.LocalAddr().String()})
			Expect(err).ToNot(HaveOccurred())
			Expect(isConnRunning()).To(BeFalse())

			// check that the proxy port is not in use anymore
			conn, err := net.DialUDP("udp", nil, proxy.LocalAddr().(*net.UDPAddr))
			Expect(err).ToNot(HaveOccurred())
			_, err = conn.Write(makePacket(1, []byte("foobar")))
			Expect(err).ToNot(HaveOccurred())
			Eventually(isConnRunning).Should(BeTrue())
			Expect(proxy.Close()).To(Succeed())
			Eventually(isConnRunning).Should(BeFalse())
		})

		It("has the correct LocalAddr and LocalPort", func() {
			proxy, err := NewQuicProxy("localhost:0", protocol.VersionWhatever, nil)
			Expect(err).ToNot(HaveOccurred())

			Expect(proxy.LocalAddr().String()).To(Equal("127.0.0.1:" + strconv.Itoa(proxy.LocalPort())))
			Expect(proxy.LocalPort()).ToNot(BeZero())

			Expect(proxy.Close()).To(Succeed())
		})
	})

	Context("Proxy tests", func() {
		var (
			serverConn            *net.UDPConn
			serverNumPacketsSent  int32
			serverReceivedPackets chan packetData
			clientConn            *net.UDPConn
			proxy                 *QuicProxy
		)

		startProxy := func(opts *Opts) {
			var err error
			proxy, err = NewQuicProxy("localhost:0", protocol.VersionWhatever, opts)
			Expect(err).ToNot(HaveOccurred())
			clientConn, err = net.DialUDP("udp", nil, proxy.LocalAddr().(*net.UDPAddr))
			Expect(err).ToNot(HaveOccurred())
		}

		// getClientDict returns a copy of the clientDict map
		getClientDict := func() map[string]*connection {
			d := make(map[string]*connection)
			proxy.mutex.Lock()
			defer proxy.mutex.Unlock()
			for k, v := range proxy.clientDict {
				d[k] = v
			}
			return d
		}

		BeforeEach(func() {
			serverReceivedPackets = make(chan packetData, 100)
			atomic.StoreInt32(&serverNumPacketsSent, 0)

			// setup a dump UDP server
			// in production this would be a QUIC server
			raddr, err := net.ResolveUDPAddr("udp", "127.0.0.1:0")
			Expect(err).ToNot(HaveOccurred())
			serverConn, err = net.ListenUDP("udp", raddr)
			Expect(err).ToNot(HaveOccurred())

			go func() {
				for {
					buf := make([]byte, protocol.MaxReceivePacketSize)
					// the ReadFromUDP will error as soon as the UDP conn is closed
					n, addr, err2 := serverConn.ReadFromUDP(buf)
					if err2 != nil {
						return
					}
					data := buf[0:n]
					serverReceivedPackets <- packetData(data)
					// echo the packet
					serverConn.WriteToUDP(data, addr)
					atomic.AddInt32(&serverNumPacketsSent, 1)
				}
			}()
		})

		AfterEach(func() {
			err := proxy.Close()
			Expect(err).ToNot(HaveOccurred())
			err = serverConn.Close()
			Expect(err).ToNot(HaveOccurred())
			err = clientConn.Close()
			Expect(err).ToNot(HaveOccurred())
			time.Sleep(200 * time.Millisecond)
		})

		Context("no packet drop", func() {
			It("relays packets from the client to the server", func() {
				startProxy(&Opts{RemoteAddr: serverConn.LocalAddr().String()})
				// send the first packet
				_, err := clientConn.Write(makePacket(1, []byte("foobar")))
				Expect(err).ToNot(HaveOccurred())

				Eventually(getClientDict).Should(HaveLen(1))
				var conn *connection
				for _, conn = range getClientDict() {
					Eventually(func() uint64 { return atomic.LoadUint64(&conn.incomingPacketCounter) }).Should(Equal(uint64(1)))
				}

				// send the second packet
				_, err = clientConn.Write(makePacket(2, []byte("decafbad")))
				Expect(err).ToNot(HaveOccurred())

				Eventually(serverReceivedPackets).Should(HaveLen(2))
				Expect(getClientDict()).To(HaveLen(1))
				Expect(string(<-serverReceivedPackets)).To(ContainSubstring("foobar"))
				Expect(string(<-serverReceivedPackets)).To(ContainSubstring("decafbad"))
			})

			It("relays packets from the server to the client", func() {
				startProxy(&Opts{RemoteAddr: serverConn.LocalAddr().String()})
				// send the first packet
				_, err := clientConn.Write(makePacket(1, []byte("foobar")))
				Expect(err).ToNot(HaveOccurred())

				Eventually(getClientDict).Should(HaveLen(1))
				var key string
				var conn *connection
				for key, conn = range getClientDict() {
					Eventually(func() uint64 { return atomic.LoadUint64(&conn.outgoingPacketCounter) }).Should(Equal(uint64(1)))
				}

				// send the second packet
				_, err = clientConn.Write(makePacket(2, []byte("decafbad")))
				Expect(err).ToNot(HaveOccurred())

				Expect(getClientDict()).To(HaveLen(1))
				Eventually(func() uint64 {
					conn := getClientDict()[key]
					return atomic.LoadUint64(&conn.outgoingPacketCounter)
				}).Should(BeEquivalentTo(2))

				clientReceivedPackets := make(chan packetData, 2)
				// receive the packets echoed by the server on client side
				go func() {
					for {
						buf := make([]byte, protocol.MaxReceivePacketSize)
						// the ReadFromUDP will error as soon as the UDP conn is closed
						n, _, err2 := clientConn.ReadFromUDP(buf)
						if err2 != nil {
							return
						}
						data := buf[0:n]
						clientReceivedPackets <- packetData(data)
					}
				}()

				Eventually(serverReceivedPackets).Should(HaveLen(2))
				Expect(atomic.LoadInt32(&serverNumPacketsSent)).To(BeEquivalentTo(2))
				Eventually(clientReceivedPackets).Should(HaveLen(2))
				Expect(string(<-clientReceivedPackets)).To(ContainSubstring("foobar"))
				Expect(string(<-clientReceivedPackets)).To(ContainSubstring("decafbad"))
			})
		})

		Context("Drop Callbacks", func() {
			It("drops incoming packets", func() {
				opts := &Opts{
					RemoteAddr: serverConn.LocalAddr().String(),
					DropPacket: func(d Direction, p uint64) bool {
						return d == DirectionIncoming && p%2 == 0
					},
				}
				startProxy(opts)

				for i := 1; i <= 6; i++ {
					_, err := clientConn.Write(makePacket(protocol.PacketNumber(i), []byte("foobar"+strconv.Itoa(i))))
					Expect(err).ToNot(HaveOccurred())
				}
				Eventually(serverReceivedPackets).Should(HaveLen(3))
				Consistently(serverReceivedPackets).Should(HaveLen(3))
			})

			It("drops outgoing packets", func() {
				const numPackets = 6
				opts := &Opts{
					RemoteAddr: serverConn.LocalAddr().String(),
					DropPacket: func(d Direction, p uint64) bool {
						return d == DirectionOutgoing && p%2 == 0
					},
				}
				startProxy(opts)

				clientReceivedPackets := make(chan packetData, numPackets)
				// receive the packets echoed by the server on client side
				go func() {
					for {
						buf := make([]byte, protocol.MaxReceivePacketSize)
						// the ReadFromUDP will error as soon as the UDP conn is closed
						n, _, err2 := clientConn.ReadFromUDP(buf)
						if err2 != nil {
							return
						}
						data := buf[0:n]
						clientReceivedPackets <- packetData(data)
					}
				}()

				for i := 1; i <= numPackets; i++ {
					_, err := clientConn.Write(makePacket(protocol.PacketNumber(i), []byte("foobar"+strconv.Itoa(i))))
					Expect(err).ToNot(HaveOccurred())
				}

				Eventually(clientReceivedPackets).Should(HaveLen(numPackets / 2))
				Consistently(clientReceivedPackets).Should(HaveLen(numPackets / 2))
			})
		})

		Context("Delay Callback", func() {
			expectDelay := func(startTime time.Time, rtt time.Duration, numRTTs int) {
				expectedReceiveTime := startTime.Add(time.Duration(numRTTs) * rtt)
				Expect(time.Now()).To(SatisfyAll(
					BeTemporally(">=", expectedReceiveTime),
					BeTemporally("<", expectedReceiveTime.Add(rtt/2)),
				))
			}

			It("delays incoming packets", func() {
				delay := 300 * time.Millisecond
				opts := &Opts{
					RemoteAddr: serverConn.LocalAddr().String(),
					// delay packet 1 by 200 ms
					// delay packet 2 by 400 ms
					// ...
					DelayPacket: func(d Direction, p uint64) time.Duration {
						if d == DirectionOutgoing {
							return 0
						}
						return time.Duration(p) * delay
					},
				}
				startProxy(opts)

				// send 3 packets
				start := time.Now()
				for i := 1; i <= 3; i++ {
					_, err := clientConn.Write(makePacket(protocol.PacketNumber(i), []byte("foobar"+strconv.Itoa(i))))
					Expect(err).ToNot(HaveOccurred())
				}
				Eventually(serverReceivedPackets).Should(HaveLen(1))
				expectDelay(start, delay, 1)
				Eventually(serverReceivedPackets).Should(HaveLen(2))
				expectDelay(start, delay, 2)
				Eventually(serverReceivedPackets).Should(HaveLen(3))
				expectDelay(start, delay, 3)
			})

			It("delays outgoing packets", func() {
				const numPackets = 3
				delay := 300 * time.Millisecond
				opts := &Opts{
					RemoteAddr: serverConn.LocalAddr().String(),
					// delay packet 1 by 200 ms
					// delay packet 2 by 400 ms
					// ...
					DelayPacket: func(d Direction, p uint64) time.Duration {
						if d == DirectionIncoming {
							return 0
						}
						return time.Duration(p) * delay
					},
				}
				startProxy(opts)

				clientReceivedPackets := make(chan packetData, numPackets)
				// receive the packets echoed by the server on client side
				go func() {
					for {
						buf := make([]byte, protocol.MaxReceivePacketSize)
						// the ReadFromUDP will error as soon as the UDP conn is closed
						n, _, err2 := clientConn.ReadFromUDP(buf)
						if err2 != nil {
							return
						}
						data := buf[0:n]
						clientReceivedPackets <- packetData(data)
					}
				}()

				start := time.Now()
				for i := 1; i <= numPackets; i++ {
					_, err := clientConn.Write(makePacket(protocol.PacketNumber(i), []byte("foobar"+strconv.Itoa(i))))
					Expect(err).ToNot(HaveOccurred())
				}
				// the packets should have arrived immediately at the server
				Eventually(serverReceivedPackets).Should(HaveLen(3))
				expectDelay(start, delay, 0)
				Eventually(clientReceivedPackets).Should(HaveLen(1))
				expectDelay(start, delay, 1)
				Eventually(clientReceivedPackets).Should(HaveLen(2))
				expectDelay(start, delay, 2)
				Eventually(clientReceivedPackets).Should(HaveLen(3))
				expectDelay(start, delay, 3)
			})
		})
	})
})
