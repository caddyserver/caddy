package h2quic

import (
	"net/http"
	"net/url"

	"golang.org/x/net/http2/hpack"

	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"
)

var _ = Describe("Request", func() {
	It("populates request", func() {
		headers := []hpack.HeaderField{
			{Name: ":path", Value: "/foo"},
			{Name: ":authority", Value: "quic.clemente.io"},
			{Name: ":method", Value: "GET"},
			{Name: "content-length", Value: "42"},
		}
		req, err := requestFromHeaders(headers)
		Expect(err).NotTo(HaveOccurred())
		Expect(req.Method).To(Equal("GET"))
		Expect(req.URL.Path).To(Equal("/foo"))
		Expect(req.Proto).To(Equal("HTTP/2.0"))
		Expect(req.ProtoMajor).To(Equal(2))
		Expect(req.ProtoMinor).To(Equal(0))
		Expect(req.ContentLength).To(Equal(int64(42)))
		Expect(req.Header).To(BeEmpty())
		Expect(req.Body).To(BeNil())
		Expect(req.Host).To(Equal("quic.clemente.io"))
		Expect(req.RequestURI).To(Equal("/foo"))
		Expect(req.TLS).ToNot(BeNil())
	})

	It("concatenates the cookie headers", func() {
		headers := []hpack.HeaderField{
			{Name: ":path", Value: "/foo"},
			{Name: ":authority", Value: "quic.clemente.io"},
			{Name: ":method", Value: "GET"},
			{Name: "cookie", Value: "cookie1=foobar1"},
			{Name: "cookie", Value: "cookie2=foobar2"},
		}
		req, err := requestFromHeaders(headers)
		Expect(err).NotTo(HaveOccurred())
		Expect(req.Header).To(Equal(http.Header{
			"Cookie": []string{"cookie1=foobar1; cookie2=foobar2"},
		}))
	})

	It("handles other headers", func() {
		headers := []hpack.HeaderField{
			{Name: ":path", Value: "/foo"},
			{Name: ":authority", Value: "quic.clemente.io"},
			{Name: ":method", Value: "GET"},
			{Name: "cache-control", Value: "max-age=0"},
			{Name: "duplicate-header", Value: "1"},
			{Name: "duplicate-header", Value: "2"},
		}
		req, err := requestFromHeaders(headers)
		Expect(err).NotTo(HaveOccurred())
		Expect(req.Header).To(Equal(http.Header{
			"Cache-Control":    []string{"max-age=0"},
			"Duplicate-Header": []string{"1", "2"},
		}))
	})

	It("errors with missing path", func() {
		headers := []hpack.HeaderField{
			{Name: ":authority", Value: "quic.clemente.io"},
			{Name: ":method", Value: "GET"},
		}
		_, err := requestFromHeaders(headers)
		Expect(err).To(MatchError(":path, :authority and :method must not be empty"))
	})

	It("errors with missing method", func() {
		headers := []hpack.HeaderField{
			{Name: ":path", Value: "/foo"},
			{Name: ":authority", Value: "quic.clemente.io"},
		}
		_, err := requestFromHeaders(headers)
		Expect(err).To(MatchError(":path, :authority and :method must not be empty"))
	})

	It("errors with missing authority", func() {
		headers := []hpack.HeaderField{
			{Name: ":path", Value: "/foo"},
			{Name: ":method", Value: "GET"},
		}
		_, err := requestFromHeaders(headers)
		Expect(err).To(MatchError(":path, :authority and :method must not be empty"))
	})

	Context("extracting the hostname from a request", func() {
		var url *url.URL

		BeforeEach(func() {
			var err error
			url, err = url.Parse("https://quic.clemente.io:1337")
			Expect(err).ToNot(HaveOccurred())
		})

		It("uses req.URL.Host", func() {
			req := &http.Request{URL: url}
			Expect(hostnameFromRequest(req)).To(Equal("quic.clemente.io:1337"))
		})

		It("uses req.URL.Host even if req.Host is available", func() {
			req := &http.Request{
				Host: "www.example.org",
				URL:  url,
			}
			Expect(hostnameFromRequest(req)).To(Equal("quic.clemente.io:1337"))
		})

		It("returns an empty hostname if nothing is set", func() {
			Expect(hostnameFromRequest(&http.Request{})).To(BeEmpty())
		})
	})
})
