package h2quic

import (
	"bytes"
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"strings"
	"sync"
	"time"

	"golang.org/x/net/http2"
	"golang.org/x/net/http2/hpack"

	quic "github.com/lucas-clemente/quic-go"
	"github.com/lucas-clemente/quic-go/internal/protocol"
	"github.com/lucas-clemente/quic-go/internal/testdata"
	"github.com/lucas-clemente/quic-go/internal/utils"
	"github.com/lucas-clemente/quic-go/qerr"

	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"
)

type mockSession struct {
	closed              bool
	closedWithError     error
	dataStream          quic.Stream
	streamToAccept      quic.Stream
	streamsToOpen       []quic.Stream
	blockOpenStreamSync bool
	blockOpenStreamChan chan struct{} // close this chan (or call Close) to make OpenStreamSync return
	streamOpenErr       error
	ctx                 context.Context
	ctxCancel           context.CancelFunc
}

func newMockSession() *mockSession {
	return &mockSession{blockOpenStreamChan: make(chan struct{})}
}

func (s *mockSession) GetOrOpenStream(id protocol.StreamID) (quic.Stream, error) {
	return s.dataStream, nil
}
func (s *mockSession) AcceptStream() (quic.Stream, error) { return s.streamToAccept, nil }
func (s *mockSession) OpenStream() (quic.Stream, error) {
	if s.streamOpenErr != nil {
		return nil, s.streamOpenErr
	}
	str := s.streamsToOpen[0]
	s.streamsToOpen = s.streamsToOpen[1:]
	return str, nil
}
func (s *mockSession) OpenStreamSync() (quic.Stream, error) {
	if s.blockOpenStreamSync {
		<-s.blockOpenStreamChan
	}
	return s.OpenStream()
}
func (s *mockSession) Close() error {
	s.ctxCancel()
	if !s.closed {
		close(s.blockOpenStreamChan)
	}
	s.closed = true
	return nil
}
func (s *mockSession) CloseWithError(_ quic.ErrorCode, e error) error {
	s.closedWithError = e
	return s.Close()
}
func (s *mockSession) LocalAddr() net.Addr {
	panic("not implemented")
}
func (s *mockSession) RemoteAddr() net.Addr {
	return &net.UDPAddr{IP: []byte{127, 0, 0, 1}, Port: 42}
}
func (s *mockSession) Context() context.Context {
	return s.ctx
}
func (s *mockSession) ConnectionState() quic.ConnectionState        { panic("not implemented") }
func (s *mockSession) AcceptUniStream() (quic.ReceiveStream, error) { panic("not implemented") }
func (s *mockSession) OpenUniStream() (quic.SendStream, error)      { panic("not implemented") }
func (s *mockSession) OpenUniStreamSync() (quic.SendStream, error)  { panic("not implemented") }

var _ = Describe("H2 server", func() {
	var (
		s                  *Server
		session            *mockSession
		dataStream         *mockStream
		origQuicListenAddr = quicListenAddr
	)

	BeforeEach(func() {
		s = &Server{
			Server: &http.Server{
				TLSConfig: testdata.GetTLSConfig(),
			},
			logger: utils.DefaultLogger,
		}
		dataStream = newMockStream(0)
		close(dataStream.unblockRead)
		session = newMockSession()
		session.dataStream = dataStream
		session.ctx, session.ctxCancel = context.WithCancel(context.Background())
		origQuicListenAddr = quicListenAddr
	})

	AfterEach(func() {
		quicListenAddr = origQuicListenAddr
	})

	Context("handling requests", func() {
		var (
			h2framer     *http2.Framer
			hpackDecoder *hpack.Decoder
			headerStream *mockStream
		)

		BeforeEach(func() {
			headerStream = &mockStream{}
			hpackDecoder = hpack.NewDecoder(4096, nil)
			h2framer = http2.NewFramer(nil, headerStream)
		})

		It("handles a sample GET request", func() {
			var handlerCalled bool
			s.Handler = http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				defer GinkgoRecover()
				Expect(r.Host).To(Equal("www.example.com"))
				Expect(r.RemoteAddr).To(Equal("127.0.0.1:42"))
				handlerCalled = true
			})
			headerStream.dataToRead.Write([]byte{
				0x0, 0x0, 0x11, 0x1, 0x5, 0x0, 0x0, 0x0, 0x5,
				// Taken from https://http2.github.io/http2-spec/compression.html#request.examples.with.huffman.coding
				0x82, 0x86, 0x84, 0x41, 0x8c, 0xf1, 0xe3, 0xc2, 0xe5, 0xf2, 0x3a, 0x6b, 0xa0, 0xab, 0x90, 0xf4, 0xff,
			})
			err := s.handleRequest(session, headerStream, &sync.Mutex{}, hpackDecoder, h2framer)
			Expect(err).NotTo(HaveOccurred())
			Eventually(func() bool { return handlerCalled }).Should(BeTrue())
			Expect(dataStream.remoteClosed).To(BeTrue())
			Expect(dataStream.reset).To(BeFalse())
		})

		It("returns 200 with an empty handler", func() {
			s.Handler = http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {})
			headerStream.dataToRead.Write([]byte{
				0x0, 0x0, 0x11, 0x1, 0x5, 0x0, 0x0, 0x0, 0x5,
				// Taken from https://http2.github.io/http2-spec/compression.html#request.examples.with.huffman.coding
				0x82, 0x86, 0x84, 0x41, 0x8c, 0xf1, 0xe3, 0xc2, 0xe5, 0xf2, 0x3a, 0x6b, 0xa0, 0xab, 0x90, 0xf4, 0xff,
			})
			err := s.handleRequest(session, headerStream, &sync.Mutex{}, hpackDecoder, h2framer)
			Expect(err).NotTo(HaveOccurred())
			Eventually(func() []byte {
				return headerStream.dataWritten.Bytes()
			}).Should(Equal([]byte{0x0, 0x0, 0x1, 0x1, 0x4, 0x0, 0x0, 0x0, 0x5, 0x88})) // 0x88 is 200
		})

		It("correctly handles a panicking handler", func() {
			s.Handler = http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				panic("foobar")
			})
			headerStream.dataToRead.Write([]byte{
				0x0, 0x0, 0x11, 0x1, 0x5, 0x0, 0x0, 0x0, 0x5,
				// Taken from https://http2.github.io/http2-spec/compression.html#request.examples.with.huffman.coding
				0x82, 0x86, 0x84, 0x41, 0x8c, 0xf1, 0xe3, 0xc2, 0xe5, 0xf2, 0x3a, 0x6b, 0xa0, 0xab, 0x90, 0xf4, 0xff,
			})
			err := s.handleRequest(session, headerStream, &sync.Mutex{}, hpackDecoder, h2framer)
			Expect(err).NotTo(HaveOccurred())
			Eventually(func() []byte {
				return headerStream.dataWritten.Bytes()
			}).Should(Equal([]byte{0x0, 0x0, 0x1, 0x1, 0x4, 0x0, 0x0, 0x0, 0x5, 0x8e})) // 0x82 is 500
		})

		It("resets the dataStream when client sends a body in GET request", func() {
			var handlerCalled bool
			s.Handler = http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				Expect(r.Host).To(Equal("www.example.com"))
				handlerCalled = true
			})
			headerStream.dataToRead.Write([]byte{
				0x0, 0x0, 0x11, 0x1, 0x4, 0x0, 0x0, 0x0, 0x5,
				// Taken from https://http2.github.io/http2-spec/compression.html#request.examples.with.huffman.coding
				0x82, 0x86, 0x84, 0x41, 0x8c, 0xf1, 0xe3, 0xc2, 0xe5, 0xf2, 0x3a, 0x6b, 0xa0, 0xab, 0x90, 0xf4, 0xff,
			})
			err := s.handleRequest(session, headerStream, &sync.Mutex{}, hpackDecoder, h2framer)
			Expect(err).NotTo(HaveOccurred())
			Eventually(func() bool { return handlerCalled }).Should(BeTrue())
			Eventually(func() bool { return dataStream.reset }).Should(BeTrue())
			Expect(dataStream.remoteClosed).To(BeFalse())
		})

		It("resets the dataStream when the body of POST request is not read", func() {
			var handlerCalled bool
			s.Handler = http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				Expect(r.Host).To(Equal("www.example.com"))
				Expect(r.Method).To(Equal("POST"))
				handlerCalled = true
			})
			headerStream.dataToRead.Write([]byte{0x0, 0x0, 0x20, 0x1, 0x24, 0x0, 0x0, 0x0, 0x5, 0x0, 0x0, 0x0, 0x0, 0xff, 0x41, 0x8c, 0xf1, 0xe3, 0xc2, 0xe5, 0xf2, 0x3a, 0x6b, 0xa0, 0xab, 0x90, 0xf4, 0xff, 0x83, 0x84, 0x87, 0x5c, 0x1, 0x37, 0x7a, 0x85, 0xed, 0x69, 0x88, 0xb4, 0xc7})
			err := s.handleRequest(session, headerStream, &sync.Mutex{}, hpackDecoder, h2framer)
			Expect(err).NotTo(HaveOccurred())
			Eventually(func() bool { return dataStream.reset }).Should(BeTrue())
			Consistently(func() bool { return dataStream.remoteClosed }).Should(BeFalse())
			Expect(handlerCalled).To(BeTrue())
		})

		It("handles a request for which the client immediately resets the data stream", func() {
			session.dataStream = nil
			var handlerCalled bool
			s.Handler = http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				handlerCalled = true
			})
			headerStream.dataToRead.Write([]byte{
				0x0, 0x0, 0x11, 0x1, 0x5, 0x0, 0x0, 0x0, 0x5,
				// Taken from https://http2.github.io/http2-spec/compression.html#request.examples.with.huffman.coding
				0x82, 0x86, 0x84, 0x41, 0x8c, 0xf1, 0xe3, 0xc2, 0xe5, 0xf2, 0x3a, 0x6b, 0xa0, 0xab, 0x90, 0xf4, 0xff,
			})
			err := s.handleRequest(session, headerStream, &sync.Mutex{}, hpackDecoder, h2framer)
			Expect(err).NotTo(HaveOccurred())
			Consistently(func() bool { return handlerCalled }).Should(BeFalse())
		})

		It("resets the dataStream when the body of POST request is not read, and the request handler replaces the request.Body", func() {
			var handlerCalled bool
			s.Handler = http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				r.Body = struct {
					io.Reader
					io.Closer
				}{}
				handlerCalled = true
			})
			headerStream.dataToRead.Write([]byte{0x0, 0x0, 0x20, 0x1, 0x24, 0x0, 0x0, 0x0, 0x5, 0x0, 0x0, 0x0, 0x0, 0xff, 0x41, 0x8c, 0xf1, 0xe3, 0xc2, 0xe5, 0xf2, 0x3a, 0x6b, 0xa0, 0xab, 0x90, 0xf4, 0xff, 0x83, 0x84, 0x87, 0x5c, 0x1, 0x37, 0x7a, 0x85, 0xed, 0x69, 0x88, 0xb4, 0xc7})
			err := s.handleRequest(session, headerStream, &sync.Mutex{}, hpackDecoder, h2framer)
			Expect(err).NotTo(HaveOccurred())
			Eventually(func() bool { return dataStream.reset }).Should(BeTrue())
			Consistently(func() bool { return dataStream.remoteClosed }).Should(BeFalse())
			Expect(handlerCalled).To(BeTrue())
		})

		It("closes the dataStream if the body of POST request was read", func() {
			var handlerCalled bool
			s.Handler = http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				Expect(r.Host).To(Equal("www.example.com"))
				Expect(r.Method).To(Equal("POST"))
				handlerCalled = true
				// read the request body
				b := make([]byte, 1000)
				n, _ := r.Body.Read(b)
				Expect(n).ToNot(BeZero())
			})
			headerStream.dataToRead.Write([]byte{0x0, 0x0, 0x20, 0x1, 0x24, 0x0, 0x0, 0x0, 0x5, 0x0, 0x0, 0x0, 0x0, 0xff, 0x41, 0x8c, 0xf1, 0xe3, 0xc2, 0xe5, 0xf2, 0x3a, 0x6b, 0xa0, 0xab, 0x90, 0xf4, 0xff, 0x83, 0x84, 0x87, 0x5c, 0x1, 0x37, 0x7a, 0x85, 0xed, 0x69, 0x88, 0xb4, 0xc7})
			dataStream.dataToRead.Write([]byte("foo=bar"))
			err := s.handleRequest(session, headerStream, &sync.Mutex{}, hpackDecoder, h2framer)
			Expect(err).NotTo(HaveOccurred())
			Eventually(func() bool { return handlerCalled }).Should(BeTrue())
			Expect(dataStream.reset).To(BeFalse())
		})

		It("ignores PRIORITY frames", func() {
			handlerCalled := make(chan struct{})
			s.Handler = http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				close(handlerCalled)
			})
			buf := &bytes.Buffer{}
			framer := http2.NewFramer(buf, nil)
			err := framer.WritePriority(10, http2.PriorityParam{Weight: 42})
			Expect(err).ToNot(HaveOccurred())
			Expect(buf.Bytes()).ToNot(BeEmpty())
			headerStream.dataToRead.Write(buf.Bytes())
			err = s.handleRequest(session, headerStream, &sync.Mutex{}, hpackDecoder, h2framer)
			Expect(err).ToNot(HaveOccurred())
			Consistently(handlerCalled).ShouldNot(BeClosed())
			Expect(dataStream.reset).To(BeFalse())
			Expect(dataStream.closed).To(BeFalse())
		})

		It("errors when non-header frames are received", func() {
			headerStream.dataToRead.Write([]byte{
				0x0, 0x0, 0x06, 0x0, 0x0, 0x0, 0x0, 0x0, 0x5,
				'f', 'o', 'o', 'b', 'a', 'r',
			})
			err := s.handleRequest(session, headerStream, &sync.Mutex{}, hpackDecoder, h2framer)
			Expect(err).To(MatchError("InvalidHeadersStreamData: expected a header frame"))
		})

		It("Cancels the request context when the datstream is closed", func() {
			var handlerCalled bool
			s.Handler = http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				defer GinkgoRecover()
				err := r.Context().Err()
				Expect(err).To(HaveOccurred())
				Expect(err.Error()).To(Equal("context canceled"))
				handlerCalled = true
			})
			headerStream.dataToRead.Write([]byte{
				0x0, 0x0, 0x11, 0x1, 0x5, 0x0, 0x0, 0x0, 0x5,
				// Taken from https://http2.github.io/http2-spec/compression.html#request.examples.with.huffman.coding
				0x82, 0x86, 0x84, 0x41, 0x8c, 0xf1, 0xe3, 0xc2, 0xe5, 0xf2, 0x3a, 0x6b, 0xa0, 0xab, 0x90, 0xf4, 0xff,
			})
			dataStream.Close()
			err := s.handleRequest(session, headerStream, &sync.Mutex{}, hpackDecoder, h2framer)
			Expect(err).NotTo(HaveOccurred())
			Eventually(func() bool { return handlerCalled }).Should(BeTrue())
			Expect(dataStream.remoteClosed).To(BeTrue())
			Expect(dataStream.reset).To(BeFalse())
		})
	})

	It("handles the header stream", func() {
		var handlerCalled bool
		s.Handler = http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			Expect(r.Host).To(Equal("www.example.com"))
			handlerCalled = true
		})
		headerStream := &mockStream{id: 3}
		headerStream.dataToRead.Write([]byte{
			0x0, 0x0, 0x11, 0x1, 0x4, 0x0, 0x0, 0x0, 0x5,
			// Taken from https://http2.github.io/http2-spec/compression.html#request.examples.with.huffman.coding
			0x82, 0x86, 0x84, 0x41, 0x8c, 0xf1, 0xe3, 0xc2, 0xe5, 0xf2, 0x3a, 0x6b, 0xa0, 0xab, 0x90, 0xf4, 0xff,
		})
		session.streamToAccept = headerStream
		go s.handleHeaderStream(session)
		Eventually(func() bool { return handlerCalled }).Should(BeTrue())
	})

	It("closes the connection if it encounters an error on the header stream", func() {
		var handlerCalled bool
		s.Handler = http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			handlerCalled = true
		})
		headerStream := &mockStream{id: 3}
		headerStream.dataToRead.Write(bytes.Repeat([]byte{0}, 100))
		session.streamToAccept = headerStream
		go s.handleHeaderStream(session)
		Consistently(func() bool { return handlerCalled }).Should(BeFalse())
		Eventually(func() bool { return session.closed }).Should(BeTrue())
		Expect(session.closedWithError).To(MatchError(qerr.Error(qerr.HeadersStreamDataDecompressFailure, "cannot read frame")))
	})

	It("supports closing after first request", func() {
		s.CloseAfterFirstRequest = true
		s.Handler = http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {})
		headerStream := &mockStream{id: 3}
		headerStream.dataToRead.Write([]byte{
			0x0, 0x0, 0x11, 0x1, 0x4, 0x0, 0x0, 0x0, 0x5,
			// Taken from https://http2.github.io/http2-spec/compression.html#request.examples.with.huffman.coding
			0x82, 0x86, 0x84, 0x41, 0x8c, 0xf1, 0xe3, 0xc2, 0xe5, 0xf2, 0x3a, 0x6b, 0xa0, 0xab, 0x90, 0xf4, 0xff,
		})
		session.streamToAccept = headerStream
		Expect(session.closed).To(BeFalse())
		go s.handleHeaderStream(session)
		Eventually(func() bool { return session.closed }).Should(BeTrue())
	})

	It("uses the default handler as fallback", func() {
		var handlerCalled bool
		http.Handle("/", http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			Expect(r.Host).To(Equal("www.example.com"))
			handlerCalled = true
		}))
		headerStream := &mockStream{id: 3}
		headerStream.dataToRead.Write([]byte{
			0x0, 0x0, 0x11, 0x1, 0x4, 0x0, 0x0, 0x0, 0x5,
			// Taken from https://http2.github.io/http2-spec/compression.html#request.examples.with.huffman.coding
			0x82, 0x86, 0x84, 0x41, 0x8c, 0xf1, 0xe3, 0xc2, 0xe5, 0xf2, 0x3a, 0x6b, 0xa0, 0xab, 0x90, 0xf4, 0xff,
		})
		session.streamToAccept = headerStream
		go s.handleHeaderStream(session)
		Eventually(func() bool { return handlerCalled }).Should(BeTrue())
	})

	Context("setting http headers", func() {
		var expected http.Header

		getExpectedHeader := func(versions []protocol.VersionNumber) http.Header {
			var versionsAsString []string
			for _, v := range versions {
				versionsAsString = append(versionsAsString, v.ToAltSvc())
			}
			return http.Header{
				"Alt-Svc": {fmt.Sprintf(`quic=":443"; ma=2592000; v="%s"`, strings.Join(versionsAsString, ","))},
			}
		}

		BeforeEach(func() {
			Expect(getExpectedHeader([]protocol.VersionNumber{99, 90, 9})).To(Equal(http.Header{"Alt-Svc": {`quic=":443"; ma=2592000; v="99,90,9"`}}))
			expected = getExpectedHeader(protocol.SupportedVersions)
		})

		It("sets proper headers with numeric port", func() {
			s.Server.Addr = ":443"
			hdr := http.Header{}
			err := s.SetQuicHeaders(hdr)
			Expect(err).NotTo(HaveOccurred())
			Expect(hdr).To(Equal(expected))
		})

		It("sets proper headers with full addr", func() {
			s.Server.Addr = "127.0.0.1:443"
			hdr := http.Header{}
			err := s.SetQuicHeaders(hdr)
			Expect(err).NotTo(HaveOccurred())
			Expect(hdr).To(Equal(expected))
		})

		It("sets proper headers with string port", func() {
			s.Server.Addr = ":https"
			hdr := http.Header{}
			err := s.SetQuicHeaders(hdr)
			Expect(err).NotTo(HaveOccurred())
			Expect(hdr).To(Equal(expected))
		})

		It("works multiple times", func() {
			s.Server.Addr = ":https"
			hdr := http.Header{}
			err := s.SetQuicHeaders(hdr)
			Expect(err).NotTo(HaveOccurred())
			Expect(hdr).To(Equal(expected))
			hdr = http.Header{}
			err = s.SetQuicHeaders(hdr)
			Expect(err).NotTo(HaveOccurred())
			Expect(hdr).To(Equal(expected))
		})
	})

	It("should error when ListenAndServe is called with s.Server nil", func() {
		err := (&Server{}).ListenAndServe()
		Expect(err).To(MatchError("use of h2quic.Server without http.Server"))
	})

	It("should error when ListenAndServeTLS is called with s.Server nil", func() {
		err := (&Server{}).ListenAndServeTLS(testdata.GetCertificatePaths())
		Expect(err).To(MatchError("use of h2quic.Server without http.Server"))
	})

	It("should nop-Close() when s.server is nil", func() {
		err := (&Server{}).Close()
		Expect(err).NotTo(HaveOccurred())
	})

	It("errors when ListenAndServer is called after Close", func() {
		serv := &Server{Server: &http.Server{}}
		Expect(serv.Close()).To(Succeed())
		err := serv.ListenAndServe()
		Expect(err).To(MatchError("Server is already closed"))
	})

	Context("ListenAndServe", func() {
		BeforeEach(func() {
			s.Server.Addr = "localhost:0"
		})

		AfterEach(func() {
			Expect(s.Close()).To(Succeed())
		})

		It("may only be called once", func() {
			cErr := make(chan error)
			for i := 0; i < 2; i++ {
				go func() {
					defer GinkgoRecover()
					err := s.ListenAndServe()
					if err != nil {
						cErr <- err
					}
				}()
			}
			err := <-cErr
			Expect(err).To(MatchError("ListenAndServe may only be called once"))
			err = s.Close()
			Expect(err).NotTo(HaveOccurred())
		}, 0.5)

		It("uses the quic.Config to start the quic server", func() {
			conf := &quic.Config{HandshakeTimeout: time.Nanosecond}
			var receivedConf *quic.Config
			quicListenAddr = func(addr string, tlsConf *tls.Config, config *quic.Config) (quic.Listener, error) {
				receivedConf = config
				return nil, errors.New("listen err")
			}
			s.QuicConfig = conf
			go s.ListenAndServe()
			Eventually(func() *quic.Config { return receivedConf }).Should(Equal(conf))
		})
	})

	Context("ListenAndServeTLS", func() {
		BeforeEach(func() {
			s.Server.Addr = "localhost:0"
		})

		AfterEach(func() {
			err := s.Close()
			Expect(err).NotTo(HaveOccurred())
		})

		It("may only be called once", func() {
			cErr := make(chan error)
			for i := 0; i < 2; i++ {
				go func() {
					defer GinkgoRecover()
					err := s.ListenAndServeTLS(testdata.GetCertificatePaths())
					if err != nil {
						cErr <- err
					}
				}()
			}
			err := <-cErr
			Expect(err).To(MatchError("ListenAndServe may only be called once"))
			err = s.Close()
			Expect(err).NotTo(HaveOccurred())
		}, 0.5)
	})

	It("closes gracefully", func() {
		err := s.CloseGracefully(0)
		Expect(err).NotTo(HaveOccurred())
	})

	It("errors when listening fails", func() {
		testErr := errors.New("listen error")
		quicListenAddr = func(addr string, tlsConf *tls.Config, config *quic.Config) (quic.Listener, error) {
			return nil, testErr
		}
		fullpem, privkey := testdata.GetCertificatePaths()
		err := ListenAndServeQUIC("", fullpem, privkey, nil)
		Expect(err).To(MatchError(testErr))
	})
})
