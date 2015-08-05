package config

import (
	"testing"

	"github.com/mholt/caddy/server"
)

func TestResolveAddr(t *testing.T) {
	// NOTE: If tests fail due to comparing to string "127.0.0.1",
	// it's possible that system env resolves with IPv6, or ::1.
	// If that happens, maybe we should use actualAddr.IP.IsLoopback()
	// for the assertion, rather than a direct string comparison.

	// NOTE: Tests with {Host: "", Port: ""} and {Host: "localhost", Port: ""}
	// will not behave the same cross-platform, so they have been omitted.

	for i, test := range []struct {
		config         server.Config
		shouldWarnErr  bool
		shouldFatalErr bool
		expectedIP     string
		expectedPort   int
	}{
		{server.Config{Host: "127.0.0.1", Port: "1234"}, false, false, "<nil>", 1234},
		{server.Config{Host: "localhost", Port: "80"}, false, false, "<nil>", 80},
		{server.Config{BindHost: "localhost", Port: "1234"}, false, false, "127.0.0.1", 1234},
		{server.Config{BindHost: "127.0.0.1", Port: "1234"}, false, false, "127.0.0.1", 1234},
		{server.Config{BindHost: "should-not-resolve", Port: "1234"}, true, false, "0.0.0.0", 1234},
		{server.Config{BindHost: "localhost", Port: "http"}, false, false, "127.0.0.1", 80},
		{server.Config{BindHost: "localhost", Port: "https"}, false, false, "127.0.0.1", 443},
		{server.Config{BindHost: "", Port: "1234"}, false, false, "<nil>", 1234},
		{server.Config{BindHost: "localhost", Port: "abcd"}, false, true, "", 0},
		{server.Config{BindHost: "127.0.0.1", Host: "should-not-be-used", Port: "1234"}, false, false, "127.0.0.1", 1234},
		{server.Config{BindHost: "localhost", Host: "should-not-be-used", Port: "1234"}, false, false, "127.0.0.1", 1234},
		{server.Config{BindHost: "should-not-resolve", Host: "localhost", Port: "1234"}, true, false, "0.0.0.0", 1234},
	} {
		actualAddr, warnErr, fatalErr := resolveAddr(test.config)

		if test.shouldFatalErr && fatalErr == nil {
			t.Errorf("Test %d: Expected error, but there wasn't any", i)
		}
		if !test.shouldFatalErr && fatalErr != nil {
			t.Errorf("Test %d: Expected no error, but there was one: %v", i, fatalErr)
		}
		if fatalErr != nil {
			continue
		}

		if test.shouldWarnErr && warnErr == nil {
			t.Errorf("Test %d: Expected warning, but there wasn't any", i)
		}
		if !test.shouldWarnErr && warnErr != nil {
			t.Errorf("Test %d: Expected no warning, but there was one: %v", i, warnErr)
		}

		if actual, expected := actualAddr.IP.String(), test.expectedIP; actual != expected {
			t.Errorf("Test %d: IP was %s but expected %s", i, actual, expected)
		}
		if actual, expected := actualAddr.Port, test.expectedPort; actual != expected {
			t.Errorf("Test %d: Port was %d but expected %d", i, actual, expected)
		}
	}
}
