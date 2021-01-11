package integration

import (
	"fmt"
	"log"
	"sync"
	"testing"

	"github.com/caddyserver/caddy/v2"
)

const (
	startPortRange = 1025
	maxPortRange   = (1 << 16) - 1 // 65535
)

type TestCaseParameter interface {
	NetworkAddresses() map[string]caddy.NetworkAddress
}
type testCaseParameters struct {
	networkAddresses map[string]caddy.NetworkAddress
}

func (tcp testCaseParameters) NetworkAddresses() map[string]caddy.NetworkAddress {
	return tcp.networkAddresses
}

type TestCase struct {
	TestName        string
	PortRangesSizes map[string]int
	TestFunc        IntegrationTest
	tcParameter     TestCaseParameter
}

var (
	testCases   = make(map[string]TestCase)
	testCasesMu sync.Mutex
)

type IntegrationTest func(*testing.T, TestCaseParameter)

func RegisterIntegrationTest(tc TestCase) {
	testCasesMu.Lock()
	defer testCasesMu.Unlock()
	if _, ok := testCases[tc.TestName]; ok {
		panic(fmt.Sprintf("integration test case already registered: %s", tc.TestName))
	}
	testCases[tc.TestName] = tc
}

func TestIntegration(t *testing.T) {
	nextPortRangeStart := startPortRange
	nextSlot := func(rangeSize int) string {
		portRange := fmt.Sprintf("%d", nextPortRangeStart)
		if rangeSize > 1 {
			portRange += fmt.Sprintf("-%d", (nextPortRangeStart + rangeSize - 1))
		}
		nextPortRangeStart += rangeSize
		return portRange
	}
	for i, tcase := range testCases {
		portRanges := make(map[string]caddy.NetworkAddress)
		for rangeName, rangeSize := range tcase.PortRangesSizes {
			portRange := nextSlot(rangeSize)
			log.Printf("The range `%s` for test `%s` received the port: %s", rangeName, tcase.TestName, portRange)
			netAddr, err := caddy.ParseNetworkAddress(caddy.JoinNetworkAddress("tcp", "", portRange))
			if err != nil {
				t.Fail()
				return
			}
			portRanges[rangeName] = netAddr
		}
		tcase.tcParameter = testCaseParameters{
			networkAddresses: portRanges,
		}
		testCases[i] = tcase
	}

	for _, tcase := range testCases {
		t.Run(tcase.TestName, func(t *testing.T) {
			tcase.TestFunc(t, tcase.tcParameter)
		})
	}
}
