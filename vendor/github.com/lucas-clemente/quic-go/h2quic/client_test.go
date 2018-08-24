package h2quic

import (
	"bytes"
	"compress/gzip"
	"context"
	"crypto/tls"
	"errors"
	"io"
	"net/http"

	"golang.org/x/net/http2"
	"golang.org/x/net/http2/hpack"

	quic "github.com/lucas-clemente/quic-go"
	"github.com/lucas-clemente/quic-go/internal/protocol"
	"github.com/lucas-clemente/quic-go/internal/utils"
	"github.com/lucas-clemente/quic-go/qerr"

	"time"

	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"
)

var _ = Describe("Client", func() {
	var (
		client       *client
		session      *mockSession
		headerStream *mockStream
		req          *http.Request
		origDialAddr = dialAddr
	)

	injectResponse := func(id protocol.StreamID, rsp *http.Response) {
		EventuallyWithOffset(0, func() bool {
			client.mutex.Lock()
			defer client.mutex.Unlock()
			_, ok := client.responses[id]
			return ok
		}).Should(BeTrue())
		rspChan := client.responses[5]
		ExpectWithOffset(0, rspChan).ToNot(BeClosed())
		rspChan <- rsp
	}

	BeforeEach(func() {
		origDialAddr = dialAddr
		hostname := "quic.clemente.io:1337"
		client = newClient(hostname, nil, &roundTripperOpts{}, nil, nil)
		Expect(client.hostname).To(Equal(hostname))
		session = newMockSession()
		session.ctx, session.ctxCancel = context.WithCancel(context.Background())
		client.session = session

		headerStream = newMockStream(3)
		client.headerStream = headerStream
		client.requestWriter = newRequestWriter(headerStream, utils.DefaultLogger)
		var err error
		req, err = http.NewRequest("GET", "https://localhost:1337", nil)
		Expect(err).ToNot(HaveOccurred())
	})

	AfterEach(func() {
		dialAddr = origDialAddr
	})

	It("saves the TLS config", func() {
		tlsConf := &tls.Config{InsecureSkipVerify: true}
		client = newClient("", tlsConf, &roundTripperOpts{}, nil, nil)
		Expect(client.tlsConf).To(Equal(tlsConf))
	})

	It("saves the QUIC config", func() {
		quicConf := &quic.Config{HandshakeTimeout: time.Nanosecond}
		client = newClient("", &tls.Config{}, &roundTripperOpts{}, quicConf, nil)
		Expect(client.config).To(Equal(quicConf))
	})

	It("uses the default QUIC config if none is give", func() {
		client = newClient("", &tls.Config{}, &roundTripperOpts{}, nil, nil)
		Expect(client.config).ToNot(BeNil())
		Expect(client.config).To(Equal(defaultQuicConfig))
	})

	It("adds the port to the hostname, if none is given", func() {
		client = newClient("quic.clemente.io", nil, &roundTripperOpts{}, nil, nil)
		Expect(client.hostname).To(Equal("quic.clemente.io:443"))
	})

	It("dials", func() {
		client = newClient("localhost:1337", nil, &roundTripperOpts{}, nil, nil)
		session.streamsToOpen = []quic.Stream{newMockStream(3), newMockStream(5)}
		dialAddr = func(hostname string, _ *tls.Config, _ *quic.Config) (quic.Session, error) {
			return session, nil
		}
		close(headerStream.unblockRead)
		done := make(chan struct{})
		go func() {
			defer GinkgoRecover()
			_, err := client.RoundTrip(req)
			Expect(err).ToNot(HaveOccurred())
			close(done)
			// fmt.Println("done")
		}()
		Eventually(func() quic.Session { return client.session }).Should(Equal(session))
		// make the go routine return
		injectResponse(5, &http.Response{})
		Eventually(done).Should(BeClosed())
	})

	It("errors when dialing fails", func() {
		testErr := errors.New("handshake error")
		client = newClient("localhost:1337", nil, &roundTripperOpts{}, nil, nil)
		dialAddr = func(hostname string, _ *tls.Config, _ *quic.Config) (quic.Session, error) {
			return nil, testErr
		}
		_, err := client.RoundTrip(req)
		Expect(err).To(MatchError(testErr))
	})

	It("uses the custom dialer, if provided", func() {
		var tlsCfg *tls.Config
		var qCfg *quic.Config
		session.streamsToOpen = []quic.Stream{newMockStream(3), newMockStream(5)}
		dialer := func(_, _ string, tlsCfgP *tls.Config, cfg *quic.Config) (quic.Session, error) {
			tlsCfg = tlsCfgP
			qCfg = cfg
			return session, nil
		}
		client = newClient("localhost:1337", nil, &roundTripperOpts{}, nil, dialer)
		done := make(chan struct{})
		go func() {
			defer GinkgoRecover()
			_, err := client.RoundTrip(req)
			Expect(err).ToNot(HaveOccurred())
			close(done)
		}()
		Eventually(func() quic.Session { return client.session }).Should(Equal(session))
		Expect(qCfg).To(Equal(client.config))
		Expect(tlsCfg).To(Equal(client.tlsConf))
		// make the go routine return
		injectResponse(5, &http.Response{})
		Eventually(done).Should(BeClosed())
	})

	It("errors if it can't open a stream", func() {
		testErr := errors.New("you shall not pass")
		client = newClient("localhost:1337", nil, &roundTripperOpts{}, nil, nil)
		session.streamOpenErr = testErr
		dialAddr = func(hostname string, _ *tls.Config, _ *quic.Config) (quic.Session, error) {
			return session, nil
		}
		_, err := client.RoundTrip(req)
		Expect(err).To(MatchError(testErr))
	})

	It("returns a request when dial fails", func() {
		testErr := errors.New("dial error")
		dialAddr = func(hostname string, _ *tls.Config, _ *quic.Config) (quic.Session, error) {
			return nil, testErr
		}
		request, err := http.NewRequest("https", "https://quic.clemente.io:1337/file1.dat", nil)
		Expect(err).ToNot(HaveOccurred())

		done := make(chan struct{})
		go func() {
			_, err := client.RoundTrip(request)
			Expect(err).To(MatchError(testErr))
			close(done)
		}()
		_, err = client.RoundTrip(request)
		Expect(err).To(MatchError(testErr))
		Eventually(done).Should(BeClosed())
	})

	Context("Doing requests", func() {
		var request *http.Request
		var dataStream *mockStream

		getRequest := func(data []byte) *http2.MetaHeadersFrame {
			r := bytes.NewReader(data)
			decoder := hpack.NewDecoder(4096, func(hf hpack.HeaderField) {})
			h2framer := http2.NewFramer(nil, r)
			frame, err := h2framer.ReadFrame()
			Expect(err).ToNot(HaveOccurred())
			mhframe := &http2.MetaHeadersFrame{HeadersFrame: frame.(*http2.HeadersFrame)}
			mhframe.Fields, err = decoder.DecodeFull(mhframe.HeadersFrame.HeaderBlockFragment())
			Expect(err).ToNot(HaveOccurred())
			return mhframe
		}

		getHeaderFields := func(f *http2.MetaHeadersFrame) map[string]string {
			fields := make(map[string]string)
			for _, hf := range f.Fields {
				fields[hf.Name] = hf.Value
			}
			return fields
		}

		BeforeEach(func() {
			var err error
			dialAddr = func(hostname string, _ *tls.Config, _ *quic.Config) (quic.Session, error) {
				return session, nil
			}
			dataStream = newMockStream(5)
			session.streamsToOpen = []quic.Stream{headerStream, dataStream}
			request, err = http.NewRequest("https", "https://quic.clemente.io:1337/file1.dat", nil)
			Expect(err).ToNot(HaveOccurred())
		})

		It("does a request", func() {
			teapot := &http.Response{
				Status:     "418 I'm a teapot",
				StatusCode: 418,
			}
			done := make(chan struct{})
			go func() {
				defer GinkgoRecover()
				rsp, err := client.RoundTrip(request)
				Expect(err).ToNot(HaveOccurred())
				Expect(rsp).To(Equal(teapot))
				Expect(rsp.Body).To(Equal(dataStream))
				Expect(rsp.ContentLength).To(BeEquivalentTo(-1))
				Expect(rsp.Request).To(Equal(request))
				close(done)
			}()

			Eventually(func() []byte { return headerStream.dataWritten.Bytes() }).ShouldNot(BeEmpty())
			injectResponse(5, teapot)
			Expect(client.headerErrored).ToNot(BeClosed())
			Eventually(done).Should(BeClosed())
		})

		It("errors if a request without a body is canceled", func() {
			done := make(chan struct{})
			ctx, cancel := context.WithCancel(context.Background())
			go func() {
				defer GinkgoRecover()
				request = request.WithContext(ctx)
				rsp, err := client.RoundTrip(request)
				Expect(err).To(MatchError(context.Canceled))
				Expect(rsp).To(BeNil())
				close(done)
			}()

			cancel()
			Eventually(done).Should(BeClosed())
			Expect(dataStream.reset).To(BeTrue())
			Expect(dataStream.canceledWrite).To(BeTrue())
			Expect(client.headerErrored).ToNot(BeClosed())
		})

		It("errors if a request with a body is canceled after the body is sent", func() {
			done := make(chan struct{})
			ctx, cancel := context.WithCancel(context.Background())
			go func() {
				defer GinkgoRecover()
				request = request.WithContext(ctx)
				request.Body = &mockBody{}
				rsp, err := client.RoundTrip(request)
				Expect(err).To(MatchError(context.Canceled))
				Expect(rsp).To(BeNil())
				close(done)
			}()

			time.Sleep(10 * time.Millisecond)
			cancel()
			Eventually(done).Should(BeClosed())
			Expect(dataStream.reset).To(BeTrue())
			Expect(dataStream.canceledWrite).To(BeTrue())
			Expect(client.headerErrored).ToNot(BeClosed())
		})

		It("errors if a request with a body is canceled before the body is sent", func() {
			done := make(chan struct{})
			ctx, cancel := context.WithCancel(context.Background())
			go func() {
				defer GinkgoRecover()
				request = request.WithContext(ctx)
				request.Body = &mockBody{}
				cancel()
				time.Sleep(10 * time.Millisecond)
				rsp, err := client.RoundTrip(request)
				Expect(err).To(MatchError(context.Canceled))
				Expect(rsp).To(BeNil())
				close(done)
			}()

			Eventually(done).Should(BeClosed())
			Expect(dataStream.reset).To(BeTrue())
			Expect(dataStream.canceledWrite).To(BeTrue())
			Expect(client.headerErrored).ToNot(BeClosed())
		})

		It("closes the quic client when encountering an error on the header stream", func() {
			headerStream.dataToRead.Write(bytes.Repeat([]byte{0}, 100))
			done := make(chan struct{})
			go func() {
				defer GinkgoRecover()
				rsp, err := client.RoundTrip(request)
				Expect(err).To(MatchError(client.headerErr))
				Expect(rsp).To(BeNil())
				close(done)
			}()

			Eventually(done).Should(BeClosed())
			Expect(client.headerErr.ErrorCode).To(Equal(qerr.InvalidHeadersStreamData))
			Expect(client.session.(*mockSession).closedWithError).To(MatchError(client.headerErr))
		})

		It("returns subsequent request if there was an error on the header stream before", func() {
			session.streamsToOpen = []quic.Stream{headerStream, dataStream, newMockStream(7)}
			headerStream.dataToRead.Write(bytes.Repeat([]byte{0}, 100))
			_, err := client.RoundTrip(request)
			Expect(err).To(BeAssignableToTypeOf(&qerr.QuicError{}))
			Expect(err.(*qerr.QuicError).ErrorCode).To(Equal(qerr.InvalidHeadersStreamData))
			// now that the first request failed due to an error on the header stream, try another request
			_, nextErr := client.RoundTrip(request)
			Expect(nextErr).To(MatchError(err))
		})

		It("blocks if no stream is available", func() {
			session.streamsToOpen = []quic.Stream{headerStream, dataStream}
			session.blockOpenStreamSync = true
			done := make(chan struct{})
			go func() {
				defer GinkgoRecover()
				_, err := client.RoundTrip(request)
				Expect(err).ToNot(HaveOccurred())
				close(done)
			}()

			Consistently(done).ShouldNot(BeClosed())
			// make the go routine return
			client.Close()
			injectResponse(5, &http.Response{})
			Eventually(done).Should(BeClosed())
		})

		Context("validating the address", func() {
			It("refuses to do requests for the wrong host", func() {
				req, err := http.NewRequest("https", "https://quic.clemente.io:1336/foobar.html", nil)
				Expect(err).ToNot(HaveOccurred())
				_, err = client.RoundTrip(req)
				Expect(err).To(MatchError("h2quic Client BUG: RoundTrip called for the wrong client (expected quic.clemente.io:1337, got quic.clemente.io:1336)"))
			})

			It("refuses to do plain HTTP requests", func() {
				req, err := http.NewRequest("https", "http://quic.clemente.io:1337/foobar.html", nil)
				Expect(err).ToNot(HaveOccurred())
				_, err = client.RoundTrip(req)
				Expect(err).To(MatchError("quic http2: unsupported scheme"))
			})

			It("adds the port for request URLs without one", func() {
				client = newClient("quic.clemente.io", nil, &roundTripperOpts{}, nil, nil)
				req, err := http.NewRequest("https", "https://quic.clemente.io/foobar.html", nil)
				Expect(err).ToNot(HaveOccurred())

				done := make(chan struct{})
				// the client.RoundTrip will block, because the encryption level is still set to Unencrypted
				go func() {
					defer GinkgoRecover()
					_, err := client.RoundTrip(req)
					Expect(err).ToNot(HaveOccurred())
					close(done)
				}()

				Consistently(done).ShouldNot(BeClosed())
				// make the go routine return
				injectResponse(5, &http.Response{})
				Eventually(done).Should(BeClosed())
			})
		})

		It("sets the EndStream header for requests without a body", func() {
			done := make(chan struct{})
			go func() {
				defer GinkgoRecover()
				client.RoundTrip(request)
				close(done)
			}()
			Eventually(func() []byte { return headerStream.dataWritten.Bytes() }).ShouldNot(BeNil())
			mhf := getRequest(headerStream.dataWritten.Bytes())
			Expect(mhf.HeadersFrame.StreamEnded()).To(BeTrue())
			// make the go routine return
			injectResponse(5, &http.Response{})
			Eventually(done).Should(BeClosed())
		})

		It("sets the EndStream header to false for requests with a body", func() {
			request.Body = &mockBody{}
			done := make(chan struct{})
			go func() {
				defer GinkgoRecover()
				client.RoundTrip(request)
				close(done)
			}()
			Eventually(func() []byte { return headerStream.dataWritten.Bytes() }).ShouldNot(BeNil())
			mhf := getRequest(headerStream.dataWritten.Bytes())
			Expect(mhf.HeadersFrame.StreamEnded()).To(BeFalse())
			// make the go routine return
			injectResponse(5, &http.Response{})
			Eventually(done).Should(BeClosed())
		})

		Context("requests containing a Body", func() {
			var requestBody []byte
			var response *http.Response

			BeforeEach(func() {
				requestBody = []byte("request body")
				body := &mockBody{}
				body.SetData(requestBody)
				request.Body = body
				response = &http.Response{
					StatusCode: 200,
					Header:     http.Header{"Content-Length": []string{"1000"}},
				}
				// fake a handshake
				client.dialOnce.Do(func() {})
				session.streamsToOpen = []quic.Stream{dataStream}
			})

			It("sends a request", func() {
				rspChan := make(chan *http.Response)
				go func() {
					defer GinkgoRecover()
					rsp, err := client.RoundTrip(request)
					Expect(err).ToNot(HaveOccurred())
					rspChan <- rsp
				}()
				injectResponse(5, response)
				Eventually(rspChan).Should(Receive(Equal(response)))
				Expect(dataStream.dataWritten.Bytes()).To(Equal(requestBody))
				Expect(dataStream.closed).To(BeTrue())
				Expect(request.Body.(*mockBody).closed).To(BeTrue())
			})

			It("returns the error that occurred when reading the body", func() {
				testErr := errors.New("testErr")
				request.Body.(*mockBody).readErr = testErr

				done := make(chan struct{})
				go func() {
					defer GinkgoRecover()
					rsp, err := client.RoundTrip(request)
					Expect(err).To(MatchError(testErr))
					Expect(rsp).To(BeNil())
					close(done)
				}()
				Eventually(done).Should(BeClosed())
				Expect(request.Body.(*mockBody).closed).To(BeTrue())
			})

			It("returns the error that occurred when closing the body", func() {
				testErr := errors.New("testErr")
				request.Body.(*mockBody).closeErr = testErr

				done := make(chan struct{})
				go func() {
					defer GinkgoRecover()
					rsp, err := client.RoundTrip(request)
					Expect(err).To(MatchError(testErr))
					Expect(rsp).To(BeNil())
					close(done)
				}()
				Eventually(done).Should(BeClosed())
				Expect(request.Body.(*mockBody).closed).To(BeTrue())
			})
		})

		Context("gzip compression", func() {
			var gzippedData []byte // a gzipped foobar
			var response *http.Response

			BeforeEach(func() {
				var b bytes.Buffer
				w := gzip.NewWriter(&b)
				w.Write([]byte("foobar"))
				w.Close()
				gzippedData = b.Bytes()
				response = &http.Response{
					StatusCode: 200,
					Header:     http.Header{"Content-Length": []string{"1000"}},
				}
			})

			It("adds the gzip header to requests", func() {
				done := make(chan struct{})
				go func() {
					defer GinkgoRecover()
					rsp, err := client.RoundTrip(request)
					Expect(err).ToNot(HaveOccurred())
					Expect(rsp).ToNot(BeNil())
					Expect(rsp.ContentLength).To(BeEquivalentTo(-1))
					Expect(rsp.Header.Get("Content-Encoding")).To(BeEmpty())
					Expect(rsp.Header.Get("Content-Length")).To(BeEmpty())
					data := make([]byte, 6)
					_, err = io.ReadFull(rsp.Body, data)
					Expect(err).ToNot(HaveOccurred())
					Expect(data).To(Equal([]byte("foobar")))
					close(done)
				}()

				dataStream.dataToRead.Write(gzippedData)
				response.Header.Add("Content-Encoding", "gzip")
				injectResponse(5, response)
				headers := getHeaderFields(getRequest(headerStream.dataWritten.Bytes()))
				Expect(headers).To(HaveKeyWithValue("accept-encoding", "gzip"))
				close(dataStream.unblockRead)
				Eventually(done).Should(BeClosed())
			})

			It("doesn't add gzip if the header disable it", func() {
				client.opts.DisableCompression = true
				done := make(chan struct{})
				go func() {
					defer GinkgoRecover()
					_, err := client.RoundTrip(request)
					Expect(err).ToNot(HaveOccurred())
					close(done)
				}()

				Eventually(func() []byte { return headerStream.dataWritten.Bytes() }).ShouldNot(BeEmpty())
				headers := getHeaderFields(getRequest(headerStream.dataWritten.Bytes()))
				Expect(headers).ToNot(HaveKey("accept-encoding"))
				// make the go routine return
				injectResponse(5, &http.Response{})
				Eventually(done).Should(BeClosed())
			})

			It("only decompresses the response if the response contains the right content-encoding header", func() {
				done := make(chan struct{})
				go func() {
					defer GinkgoRecover()
					rsp, err := client.RoundTrip(request)
					Expect(err).ToNot(HaveOccurred())
					Expect(rsp).ToNot(BeNil())
					data := make([]byte, 11)
					rsp.Body.Read(data)
					Expect(rsp.ContentLength).ToNot(BeEquivalentTo(-1))
					Expect(data).To(Equal([]byte("not gzipped")))
					close(done)
				}()

				dataStream.dataToRead.Write([]byte("not gzipped"))
				injectResponse(5, response)
				headers := getHeaderFields(getRequest(headerStream.dataWritten.Bytes()))
				Expect(headers).To(HaveKeyWithValue("accept-encoding", "gzip"))
				Eventually(done).Should(BeClosed())
			})

			It("doesn't add the gzip header for requests that have the accept-enconding set", func() {
				request.Header.Add("accept-encoding", "gzip")
				done := make(chan struct{})
				go func() {
					defer GinkgoRecover()
					rsp, err := client.RoundTrip(request)
					Expect(err).ToNot(HaveOccurred())
					data := make([]byte, 12)
					_, err = rsp.Body.Read(data)
					Expect(err).ToNot(HaveOccurred())
					Expect(rsp.ContentLength).ToNot(BeEquivalentTo(-1))
					Expect(data).To(Equal([]byte("gzipped data")))
					close(done)
				}()

				dataStream.dataToRead.Write([]byte("gzipped data"))
				injectResponse(5, response)
				headers := getHeaderFields(getRequest(headerStream.dataWritten.Bytes()))
				Expect(headers).To(HaveKeyWithValue("accept-encoding", "gzip"))
				Eventually(done).Should(BeClosed())
			})
		})

		Context("handling the header stream", func() {
			var h2framer *http2.Framer

			BeforeEach(func() {
				h2framer = http2.NewFramer(&headerStream.dataToRead, nil)
				client.responses[23] = make(chan *http.Response)
			})

			It("reads header values from a response", func() {
				// Taken from https://http2.github.io/http2-spec/compression.html#request.examples.with.huffman.coding
				data := []byte{0x48, 0x03, 0x33, 0x30, 0x32, 0x58, 0x07, 0x70, 0x72, 0x69, 0x76, 0x61, 0x74, 0x65, 0x61, 0x1d, 0x4d, 0x6f, 0x6e, 0x2c, 0x20, 0x32, 0x31, 0x20, 0x4f, 0x63, 0x74, 0x20, 0x32, 0x30, 0x31, 0x33, 0x20, 0x32, 0x30, 0x3a, 0x31, 0x33, 0x3a, 0x32, 0x31, 0x20, 0x47, 0x4d, 0x54, 0x6e, 0x17, 0x68, 0x74, 0x74, 0x70, 0x73, 0x3a, 0x2f, 0x2f, 0x77, 0x77, 0x77, 0x2e, 0x65, 0x78, 0x61, 0x6d, 0x70, 0x6c, 0x65, 0x2e, 0x63, 0x6f, 0x6d}
				headerStream.dataToRead.Write([]byte{0x0, 0x0, byte(len(data)), 0x1, 0x5, 0x0, 0x0, 0x0, 23})
				headerStream.dataToRead.Write(data)
				go client.handleHeaderStream()
				var rsp *http.Response
				Eventually(client.responses[23]).Should(Receive(&rsp))
				Expect(rsp).ToNot(BeNil())
				Expect(rsp.Proto).To(Equal("HTTP/2.0"))
				Expect(rsp.ProtoMajor).To(BeEquivalentTo(2))
				Expect(rsp.StatusCode).To(BeEquivalentTo(302))
				Expect(rsp.Status).To(Equal("302 Found"))
				Expect(rsp.Header).To(HaveKeyWithValue("Location", []string{"https://www.example.com"}))
				Expect(rsp.Header).To(HaveKeyWithValue("Cache-Control", []string{"private"}))
			})

			It("errors if the H2 frame is not a HeadersFrame", func() {
				h2framer.WritePing(true, [8]byte{0, 0, 0, 0, 0, 0, 0, 0})
				client.handleHeaderStream()
				Eventually(client.headerErrored).Should(BeClosed())
				Expect(client.headerErr).To(MatchError(qerr.Error(qerr.InvalidHeadersStreamData, "not a headers frame")))
			})

			It("errors if it can't read the HPACK encoded header fields", func() {
				h2framer.WriteHeaders(http2.HeadersFrameParam{
					StreamID:      23,
					EndHeaders:    true,
					BlockFragment: []byte("invalid HPACK data"),
				})
				client.handleHeaderStream()
				Eventually(client.headerErrored).Should(BeClosed())
				Expect(client.headerErr.ErrorCode).To(Equal(qerr.InvalidHeadersStreamData))
				Expect(client.headerErr.ErrorMessage).To(ContainSubstring("cannot read header fields"))
			})

			It("errors if the stream cannot be found", func() {
				var headers bytes.Buffer
				enc := hpack.NewEncoder(&headers)
				enc.WriteField(hpack.HeaderField{Name: ":status", Value: "200"})
				err := h2framer.WriteHeaders(http2.HeadersFrameParam{
					StreamID:      1337,
					EndHeaders:    true,
					BlockFragment: headers.Bytes(),
				})
				Expect(err).ToNot(HaveOccurred())
				client.handleHeaderStream()
				Eventually(client.headerErrored).Should(BeClosed())
				Expect(client.headerErr.ErrorCode).To(Equal(qerr.InvalidHeadersStreamData))
				Expect(client.headerErr.ErrorMessage).To(ContainSubstring("response channel for stream 1337 not found"))
			})
		})
	})
})
