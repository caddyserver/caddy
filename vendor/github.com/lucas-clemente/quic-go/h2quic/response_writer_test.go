package h2quic

import (
	"bytes"
	"context"
	"io"
	"net/http"
	"sync"
	"time"

	"golang.org/x/net/http2"
	"golang.org/x/net/http2/hpack"

	quic "github.com/lucas-clemente/quic-go"
	"github.com/lucas-clemente/quic-go/internal/protocol"
	"github.com/lucas-clemente/quic-go/internal/utils"
	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"
)

type mockStream struct {
	id            protocol.StreamID
	dataToRead    bytes.Buffer
	dataWritten   bytes.Buffer
	reset         bool
	canceledWrite bool
	closed        bool
	remoteClosed  bool

	unblockRead chan struct{}
	ctx         context.Context
	ctxCancel   context.CancelFunc
}

var _ quic.Stream = &mockStream{}

func newMockStream(id protocol.StreamID) *mockStream {
	s := &mockStream{
		id:          id,
		unblockRead: make(chan struct{}),
	}
	s.ctx, s.ctxCancel = context.WithCancel(context.Background())
	return s
}

func (s *mockStream) Close() error                          { s.closed = true; s.ctxCancel(); return nil }
func (s *mockStream) CancelRead(quic.ErrorCode) error       { s.reset = true; return nil }
func (s *mockStream) CancelWrite(quic.ErrorCode) error      { s.canceledWrite = true; return nil }
func (s *mockStream) CloseRemote(offset protocol.ByteCount) { s.remoteClosed = true; s.ctxCancel() }
func (s mockStream) StreamID() protocol.StreamID            { return s.id }
func (s *mockStream) Context() context.Context              { return s.ctx }
func (s *mockStream) SetDeadline(time.Time) error           { panic("not implemented") }
func (s *mockStream) SetReadDeadline(time.Time) error       { panic("not implemented") }
func (s *mockStream) SetWriteDeadline(time.Time) error      { panic("not implemented") }

func (s *mockStream) Read(p []byte) (int, error) {
	n, _ := s.dataToRead.Read(p)
	if n == 0 { // block if there's no data
		<-s.unblockRead
		return 0, io.EOF
	}
	return n, nil // never return an EOF
}
func (s *mockStream) Write(p []byte) (int, error) { return s.dataWritten.Write(p) }

var _ = Describe("Response Writer", func() {
	var (
		w            *responseWriter
		headerStream *mockStream
		dataStream   *mockStream
	)

	BeforeEach(func() {
		headerStream = &mockStream{}
		dataStream = &mockStream{}
		w = newResponseWriter(headerStream, &sync.Mutex{}, dataStream, 5, utils.DefaultLogger)
	})

	decodeHeaderFields := func() map[string][]string {
		fields := make(map[string][]string)
		decoder := hpack.NewDecoder(4096, func(hf hpack.HeaderField) {})
		h2framer := http2.NewFramer(nil, bytes.NewReader(headerStream.dataWritten.Bytes()))

		frame, err := h2framer.ReadFrame()
		Expect(err).ToNot(HaveOccurred())
		Expect(frame).To(BeAssignableToTypeOf(&http2.HeadersFrame{}))
		hframe := frame.(*http2.HeadersFrame)
		mhframe := &http2.MetaHeadersFrame{HeadersFrame: hframe}
		Expect(mhframe.StreamID).To(BeEquivalentTo(5))
		mhframe.Fields, err = decoder.DecodeFull(hframe.HeaderBlockFragment())
		Expect(err).ToNot(HaveOccurred())
		for _, p := range mhframe.Fields {
			fields[p.Name] = append(fields[p.Name], p.Value)
		}
		return fields
	}

	It("writes status", func() {
		w.WriteHeader(http.StatusTeapot)
		fields := decodeHeaderFields()
		Expect(fields).To(HaveLen(1))
		Expect(fields).To(HaveKeyWithValue(":status", []string{"418"}))
	})

	It("writes headers", func() {
		w.Header().Add("content-length", "42")
		w.WriteHeader(http.StatusTeapot)
		fields := decodeHeaderFields()
		Expect(fields).To(HaveKeyWithValue("content-length", []string{"42"}))
	})

	It("writes multiple headers with the same name", func() {
		const cookie1 = "test1=1; Max-Age=7200; path=/"
		const cookie2 = "test2=2; Max-Age=7200; path=/"
		w.Header().Add("set-cookie", cookie1)
		w.Header().Add("set-cookie", cookie2)
		w.WriteHeader(http.StatusTeapot)
		fields := decodeHeaderFields()
		Expect(fields).To(HaveKey("set-cookie"))
		cookies := fields["set-cookie"]
		Expect(cookies).To(ContainElement(cookie1))
		Expect(cookies).To(ContainElement(cookie2))
	})

	It("writes data", func() {
		n, err := w.Write([]byte("foobar"))
		Expect(n).To(Equal(6))
		Expect(err).ToNot(HaveOccurred())
		// Should have written 200 on the header stream
		fields := decodeHeaderFields()
		Expect(fields).To(HaveKeyWithValue(":status", []string{"200"}))
		// And foobar on the data stream
		Expect(dataStream.dataWritten.Bytes()).To(Equal([]byte("foobar")))
	})

	It("writes data after WriteHeader is called", func() {
		w.WriteHeader(http.StatusTeapot)
		n, err := w.Write([]byte("foobar"))
		Expect(n).To(Equal(6))
		Expect(err).ToNot(HaveOccurred())
		// Should have written 418 on the header stream
		fields := decodeHeaderFields()
		Expect(fields).To(HaveKeyWithValue(":status", []string{"418"}))
		// And foobar on the data stream
		Expect(dataStream.dataWritten.Bytes()).To(Equal([]byte("foobar")))
	})

	It("does not WriteHeader() twice", func() {
		w.WriteHeader(200)
		w.WriteHeader(500)
		fields := decodeHeaderFields()
		Expect(fields).To(HaveLen(1))
		Expect(fields).To(HaveKeyWithValue(":status", []string{"200"}))
	})

	It("doesn't allow writes if the status code doesn't allow a body", func() {
		w.WriteHeader(304)
		n, err := w.Write([]byte("foobar"))
		Expect(n).To(BeZero())
		Expect(err).To(MatchError(http.ErrBodyNotAllowed))
		Expect(dataStream.dataWritten.Bytes()).To(HaveLen(0))
	})
})
