package caddy

import (
	"reflect"
	"sync"
	"testing"

	"github.com/mholt/caddy/server"
)

func TestDefaultInput(t *testing.T) {
	if actual, expected := string(DefaultInput().Body()), ":2015\nroot ."; actual != expected {
		t.Errorf("Host=%s; Port=%s; Root=%s;\nEXPECTED: '%s'\n  ACTUAL: '%s'", Host, Port, Root, expected, actual)
	}

	// next few tests simulate user providing -host and/or -port flags

	Host = "not-localhost.com"
	if actual, expected := string(DefaultInput().Body()), "not-localhost.com:443\nroot ."; actual != expected {
		t.Errorf("Host=%s; Port=%s; Root=%s;\nEXPECTED: '%s'\n  ACTUAL: '%s'", Host, Port, Root, expected, actual)
	}

	Host = "[::1]"
	if actual, expected := string(DefaultInput().Body()), "[::1]:2015\nroot ."; actual != expected {
		t.Errorf("Host=%s; Port=%s; Root=%s;\nEXPECTED: '%s'\n  ACTUAL: '%s'", Host, Port, Root, expected, actual)
	}

	Host = "127.0.1.1"
	if actual, expected := string(DefaultInput().Body()), "127.0.1.1:2015\nroot ."; actual != expected {
		t.Errorf("Host=%s; Port=%s; Root=%s;\nEXPECTED: '%s'\n  ACTUAL: '%s'", Host, Port, Root, expected, actual)
	}

	Host = "not-localhost.com"
	Port = "1234"
	if actual, expected := string(DefaultInput().Body()), "not-localhost.com:1234\nroot ."; actual != expected {
		t.Errorf("Host=%s; Port=%s; Root=%s;\nEXPECTED: '%s'\n  ACTUAL: '%s'", Host, Port, Root, expected, actual)
	}

	Host = DefaultHost
	Port = "1234"
	if actual, expected := string(DefaultInput().Body()), ":1234\nroot ."; actual != expected {
		t.Errorf("Host=%s; Port=%s; Root=%s;\nEXPECTED: '%s'\n  ACTUAL: '%s'", Host, Port, Root, expected, actual)
	}
}

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
		{server.Config{BindHost: "should-not-resolve", Port: "1234"}, true, false, "<nil>", 1234},
		{server.Config{BindHost: "localhost", Port: "http"}, false, false, "127.0.0.1", 80},
		{server.Config{BindHost: "localhost", Port: "https"}, false, false, "127.0.0.1", 443},
		{server.Config{BindHost: "", Port: "1234"}, false, false, "<nil>", 1234},
		{server.Config{BindHost: "localhost", Port: "abcd"}, false, true, "", 0},
		{server.Config{BindHost: "127.0.0.1", Host: "should-not-be-used", Port: "1234"}, false, false, "127.0.0.1", 1234},
		{server.Config{BindHost: "localhost", Host: "should-not-be-used", Port: "1234"}, false, false, "127.0.0.1", 1234},
		{server.Config{BindHost: "should-not-resolve", Host: "localhost", Port: "1234"}, true, false, "<nil>", 1234},
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

func TestMakeOnces(t *testing.T) {
	directives := []directive{
		{"dummy", nil},
		{"dummy2", nil},
	}
	directiveOrder = directives
	onces := makeOnces()
	if len(onces) != len(directives) {
		t.Errorf("onces had len %d , expected %d", len(onces), len(directives))
	}
	expected := map[string]*sync.Once{
		"dummy":  new(sync.Once),
		"dummy2": new(sync.Once),
	}
	if !reflect.DeepEqual(onces, expected) {
		t.Errorf("onces was %v, expected %v", onces, expected)
	}
}

func TestMakeStorages(t *testing.T) {
	directives := []directive{
		{"dummy", nil},
		{"dummy2", nil},
	}
	directiveOrder = directives
	storages := makeStorages()
	if len(storages) != len(directives) {
		t.Errorf("storages had len %d , expected %d", len(storages), len(directives))
	}
	expected := map[string]interface{}{
		"dummy":  nil,
		"dummy2": nil,
	}
	if !reflect.DeepEqual(storages, expected) {
		t.Errorf("storages was %v, expected %v", storages, expected)
	}
}

func TestValidDirective(t *testing.T) {
	directives := []directive{
		{"dummy", nil},
		{"dummy2", nil},
	}
	directiveOrder = directives
	for i, test := range []struct {
		directive string
		valid     bool
	}{
		{"dummy", true},
		{"dummy2", true},
		{"dummy3", false},
	} {
		if actual, expected := validDirective(test.directive), test.valid; actual != expected {
			t.Errorf("Test %d: valid was %t, expected %t", i, actual, expected)
		}
	}
}
