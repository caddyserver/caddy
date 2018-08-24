package handshake

import (
	"encoding/asn1"
	"net"
	"time"

	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"
)

var _ = Describe("Cookie Generator", func() {
	var cookieGen *CookieGenerator

	BeforeEach(func() {
		var err error
		cookieGen, err = NewCookieGenerator()
		Expect(err).ToNot(HaveOccurred())
	})

	It("generates a Cookie", func() {
		ip := net.IPv4(127, 0, 0, 1)
		token, err := cookieGen.NewToken(&net.UDPAddr{IP: ip, Port: 1337})
		Expect(err).ToNot(HaveOccurred())
		Expect(token).ToNot(BeEmpty())
	})

	It("works with nil tokens", func() {
		cookie, err := cookieGen.DecodeToken(nil)
		Expect(err).ToNot(HaveOccurred())
		Expect(cookie).To(BeNil())
	})

	It("accepts a valid cookie", func() {
		ip := net.IPv4(192, 168, 0, 1)
		token, err := cookieGen.NewToken(&net.UDPAddr{IP: ip, Port: 1337})
		Expect(err).ToNot(HaveOccurred())
		cookie, err := cookieGen.DecodeToken(token)
		Expect(err).ToNot(HaveOccurred())
		Expect(cookie.RemoteAddr).To(Equal("192.168.0.1"))
		// the time resolution of the Cookie is just 1 second
		// if Cookie generation and this check happen in "different seconds", the difference will be between 1 and 2 seconds
		Expect(cookie.SentTime).To(BeTemporally("~", time.Now(), 2*time.Second))
	})

	It("rejects invalid tokens", func() {
		_, err := cookieGen.DecodeToken([]byte("invalid token"))
		Expect(err).To(HaveOccurred())
	})

	It("rejects tokens that cannot be decoded", func() {
		token, err := cookieGen.cookieProtector.NewToken([]byte("foobar"))
		Expect(err).ToNot(HaveOccurred())
		_, err = cookieGen.DecodeToken(token)
		Expect(err).To(HaveOccurred())
	})

	It("rejects tokens that can be decoded, but have additional payload", func() {
		t, err := asn1.Marshal(token{Data: []byte("foobar")})
		Expect(err).ToNot(HaveOccurred())
		t = append(t, []byte("rest")...)
		enc, err := cookieGen.cookieProtector.NewToken(t)
		Expect(err).ToNot(HaveOccurred())
		_, err = cookieGen.DecodeToken(enc)
		Expect(err).To(MatchError("rest when unpacking token: 4"))
	})

	// we don't generate tokens that have no data, but we should be able to handle them if we receive one for whatever reason
	It("doesn't panic if a tokens has no data", func() {
		t, err := asn1.Marshal(token{Data: []byte("")})
		Expect(err).ToNot(HaveOccurred())
		enc, err := cookieGen.cookieProtector.NewToken(t)
		Expect(err).ToNot(HaveOccurred())
		_, err = cookieGen.DecodeToken(enc)
		Expect(err).ToNot(HaveOccurred())
	})

	It("works with an IPv6 addresses ", func() {
		addresses := []string{
			"2001:db8::68",
			"2001:0000:4136:e378:8000:63bf:3fff:fdd2",
			"2001::1",
			"ff01:0:0:0:0:0:0:2",
		}
		for _, addr := range addresses {
			ip := net.ParseIP(addr)
			Expect(ip).ToNot(BeNil())
			raddr := &net.UDPAddr{IP: ip, Port: 1337}
			token, err := cookieGen.NewToken(raddr)
			Expect(err).ToNot(HaveOccurred())
			cookie, err := cookieGen.DecodeToken(token)
			Expect(err).ToNot(HaveOccurred())
			Expect(cookie.RemoteAddr).To(Equal(ip.String()))
			// the time resolution of the Cookie is just 1 second
			// if Cookie generation and this check happen in "different seconds", the difference will be between 1 and 2 seconds
			Expect(cookie.SentTime).To(BeTemporally("~", time.Now(), 2*time.Second))
		}
	})

	It("uses the string representation an address that is not a UDP address", func() {
		raddr := &net.TCPAddr{IP: net.IPv4(192, 168, 13, 37), Port: 1337}
		token, err := cookieGen.NewToken(raddr)
		Expect(err).ToNot(HaveOccurred())
		cookie, err := cookieGen.DecodeToken(token)
		Expect(err).ToNot(HaveOccurred())
		Expect(cookie.RemoteAddr).To(Equal("192.168.13.37:1337"))
		// the time resolution of the Cookie is just 1 second
		// if Cookie generation and this check happen in "different seconds", the difference will be between 1 and 2 seconds
		Expect(cookie.SentTime).To(BeTemporally("~", time.Now(), 2*time.Second))
	})
})
