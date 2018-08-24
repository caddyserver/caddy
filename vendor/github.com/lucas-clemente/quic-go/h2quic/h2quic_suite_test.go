package h2quic

import (
	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"

	"testing"
)

func TestH2quic(t *testing.T) {
	RegisterFailHandler(Fail)
	RunSpecs(t, "H2quic Suite")
}
