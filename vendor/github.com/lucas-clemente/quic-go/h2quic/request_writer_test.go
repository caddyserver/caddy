package h2quic

import (
	"bytes"
	"net/http"
	"net/url"
	"strconv"
	"strings"

	"golang.org/x/net/http2"
	"golang.org/x/net/http2/hpack"

	"github.com/lucas-clemente/quic-go/internal/utils"
	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"
)

var _ = Describe("Request", func() {
	var (
		rw           *requestWriter
		headerStream *mockStream
		decoder      *hpack.Decoder
	)

	BeforeEach(func() {
		headerStream = &mockStream{}
		rw = newRequestWriter(headerStream, utils.DefaultLogger)
		decoder = hpack.NewDecoder(4096, func(hf hpack.HeaderField) {})
	})

	decode := func(p []byte) (*http2.HeadersFrame, map[string] /* HeaderField.Name */ string /* HeaderField.Value */) {
		framer := http2.NewFramer(nil, bytes.NewReader(p))
		frame, err := framer.ReadFrame()
		Expect(err).ToNot(HaveOccurred())
		headerFrame := frame.(*http2.HeadersFrame)
		fields, err := decoder.DecodeFull(headerFrame.HeaderBlockFragment())
		Expect(err).ToNot(HaveOccurred())
		values := make(map[string]string)
		for _, headerField := range fields {
			values[headerField.Name] = headerField.Value
		}
		return headerFrame, values
	}

	It("writes a GET request", func() {
		req, err := http.NewRequest("GET", "https://quic.clemente.io/index.html?foo=bar", nil)
		Expect(err).ToNot(HaveOccurred())
		rw.WriteRequest(req, 1337, true, false)
		headerFrame, headerFields := decode(headerStream.dataWritten.Bytes())
		Expect(headerFrame.StreamID).To(Equal(uint32(1337)))
		Expect(headerFrame.HasPriority()).To(BeTrue())
		Expect(headerFields).To(HaveKeyWithValue(":authority", "quic.clemente.io"))
		Expect(headerFields).To(HaveKeyWithValue(":method", "GET"))
		Expect(headerFields).To(HaveKeyWithValue(":path", "/index.html?foo=bar"))
		Expect(headerFields).To(HaveKeyWithValue(":scheme", "https"))
		Expect(headerFields).ToNot(HaveKey("accept-encoding"))
	})

	It("sets the EndStream header", func() {
		req, err := http.NewRequest("GET", "https://quic.clemente.io/", nil)
		Expect(err).ToNot(HaveOccurred())
		rw.WriteRequest(req, 1337, true, false)
		headerFrame, _ := decode(headerStream.dataWritten.Bytes())
		Expect(headerFrame.StreamEnded()).To(BeTrue())
	})

	It("doesn't set the EndStream header, if requested", func() {
		req, err := http.NewRequest("GET", "https://quic.clemente.io/", nil)
		Expect(err).ToNot(HaveOccurred())
		rw.WriteRequest(req, 1337, false, false)
		headerFrame, _ := decode(headerStream.dataWritten.Bytes())
		Expect(headerFrame.StreamEnded()).To(BeFalse())
	})

	It("requests gzip compression, if requested", func() {
		req, err := http.NewRequest("GET", "https://quic.clemente.io/index.html?foo=bar", nil)
		Expect(err).ToNot(HaveOccurred())
		rw.WriteRequest(req, 1337, true, true)
		_, headerFields := decode(headerStream.dataWritten.Bytes())
		Expect(headerFields).To(HaveKeyWithValue("accept-encoding", "gzip"))
	})

	It("writes a POST request", func() {
		form := url.Values{}
		form.Add("foo", "bar")
		req, err := http.NewRequest("POST", "https://quic.clemente.io/upload.html", strings.NewReader(form.Encode()))
		Expect(err).ToNot(HaveOccurred())
		rw.WriteRequest(req, 5, true, false)
		_, headerFields := decode(headerStream.dataWritten.Bytes())
		Expect(headerFields).To(HaveKeyWithValue(":method", "POST"))
		Expect(headerFields).To(HaveKey("content-length"))
		contentLength, err := strconv.Atoi(headerFields["content-length"])
		Expect(err).ToNot(HaveOccurred())
		Expect(contentLength).To(BeNumerically(">", 0))
	})

	It("sends cookies", func() {
		req, err := http.NewRequest("GET", "https://quic.clemente.io/", nil)
		Expect(err).ToNot(HaveOccurred())
		cookie1 := &http.Cookie{
			Name:  "Cookie #1",
			Value: "Value #1",
		}
		cookie2 := &http.Cookie{
			Name:  "Cookie #2",
			Value: "Value #2",
		}
		req.AddCookie(cookie1)
		req.AddCookie(cookie2)
		rw.WriteRequest(req, 11, true, false)
		_, headerFields := decode(headerStream.dataWritten.Bytes())
		// TODO(lclemente): Remove Or() once we drop support for Go 1.8.
		Expect(headerFields).To(Or(
			HaveKeyWithValue("cookie", "Cookie #1=Value #1; Cookie #2=Value #2"),
			HaveKeyWithValue("cookie", `Cookie #1="Value #1"; Cookie #2="Value #2"`),
		))
	})
})
