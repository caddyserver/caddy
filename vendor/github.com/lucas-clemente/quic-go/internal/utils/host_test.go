package utils

import (
	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"
)

var _ = Describe("Hostname", func() {
	It("gets the hostname from an URL", func() {
		h, err := HostnameFromAddr("https://quic.clemente.io/file.dat?param=true&param2=false")
		Expect(err).ToNot(HaveOccurred())
		Expect(h).To(Equal("quic.clemente.io"))
	})

	It("gets the hostname from an URL with a port number", func() {
		h, err := HostnameFromAddr("https://quic.clemente.io:6121/file.dat")
		Expect(err).ToNot(HaveOccurred())
		Expect(h).To(Equal("quic.clemente.io"))
	})

	It("gets the hostname from an URL containing username and password", func() {
		h, err := HostnameFromAddr("https://user:password@quic.clemente.io:6121/file.dat")
		Expect(err).ToNot(HaveOccurred())
		Expect(h).To(Equal("quic.clemente.io"))
	})

	It("gets local hostnames", func() {
		h, err := HostnameFromAddr("https://localhost/file.dat")
		Expect(err).ToNot(HaveOccurred())
		Expect(h).To(Equal("localhost"))
	})

	It("gets the hostname for other protocols", func() {
		h, err := HostnameFromAddr("ftp://quic.clemente.io:6121/file.dat")
		Expect(err).ToNot(HaveOccurred())
		Expect(h).To(Equal("quic.clemente.io"))
	})

	It("gets an IP", func() {
		h, err := HostnameFromAddr("https://1.3.3.7:6121/file.dat")
		Expect(err).ToNot(HaveOccurred())
		Expect(h).To(Equal("1.3.3.7"))
	})

	It("errors on malformed URLs", func() {
		_, err := HostnameFromAddr("://quic.clemente.io:6121/file.dat")
		Expect(err).To(HaveOccurred())
	})
})
