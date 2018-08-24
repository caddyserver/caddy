package congestion

import (
	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"

	"testing"
)

func TestCongestion(t *testing.T) {
	RegisterFailHandler(Fail)
	RunSpecs(t, "Congestion Suite")
}
