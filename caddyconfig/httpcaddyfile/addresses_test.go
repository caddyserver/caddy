package httpcaddyfile

import (
	"strings"
	"testing"
)

func TestParseAddress(t *testing.T) {
	for i, test := range []struct {
		input                    string
		scheme, host, port, path string
		shouldErr                bool
	}{
		{`localhost`, "", "localhost", "", "", false},
		{`localhost:1234`, "", "localhost", "1234", "", false},
		{`localhost:`, "", "localhost", "", "", false},
		{`0.0.0.0`, "", "0.0.0.0", "", "", false},
		{`127.0.0.1:1234`, "", "127.0.0.1", "1234", "", false},
		{`:1234`, "", "", "1234", "", false},
		{`[::1]`, "", "::1", "", "", false},
		{`[::1]:1234`, "", "::1", "1234", "", false},
		{`:`, "", "", "", "", false},
		{`:http`, "", "", "", "", true},
		{`:https`, "", "", "", "", true},
		{`localhost:http`, "", "", "", "", true}, // using service name in port is verboten, as of Go 1.12.8
		{`localhost:https`, "", "", "", "", true},
		{`http://localhost:https`, "", "", "", "", true}, // conflict
		{`http://localhost:http`, "", "", "", "", true},  // repeated scheme
		{`host:https/path`, "", "", "", "", true},
		{`http://localhost:443`, "", "", "", "", true}, // not conventional
		{`https://localhost:80`, "", "", "", "", true}, // not conventional
		{`http://localhost`, "http", "localhost", "80", "", false},
		{`https://localhost`, "https", "localhost", "443", "", false},
		{`http://127.0.0.1`, "http", "127.0.0.1", "80", "", false},
		{`https://127.0.0.1`, "https", "127.0.0.1", "443", "", false},
		{`http://[::1]`, "http", "::1", "80", "", false},
		{`http://localhost:1234`, "http", "localhost", "1234", "", false},
		{`https://127.0.0.1:1234`, "https", "127.0.0.1", "1234", "", false},
		{`http://[::1]:1234`, "http", "::1", "1234", "", false},
		{``, "", "", "", "", false},
		{`::1`, "", "::1", "", "", true},
		{`localhost::`, "", "localhost::", "", "", true},
		{`#$%@`, "", "", "", "", true},
		{`host/path`, "", "host", "", "/path", false},
		{`http://host/`, "http", "host", "80", "/", false},
		{`//asdf`, "", "asdf", "", "", false},
		{`:1234/asdf`, "", "", "1234", "/asdf", false},
		{`http://host/path`, "http", "host", "80", "/path", false},
		{`https://host:443/path/foo`, "https", "host", "443", "/path/foo", false},
		{`host:80/path`, "", "host", "80", "/path", false},
		{`/path`, "", "", "", "/path", false},
	} {
		actual, err := ParseAddress(test.input)

		if err != nil && !test.shouldErr {
			t.Errorf("Test %d (%s): Expected no error, but had error: %v", i, test.input, err)
		}
		if err == nil && test.shouldErr {
			t.Errorf("Test %d (%s): Expected error, but had none", i, test.input)
		}

		if !test.shouldErr && actual.Original != test.input {
			t.Errorf("Test %d (%s): Expected original '%s', got '%s'", i, test.input, test.input, actual.Original)
		}
		if actual.Scheme != test.scheme {
			t.Errorf("Test %d (%s): Expected scheme '%s', got '%s'", i, test.input, test.scheme, actual.Scheme)
		}
		if actual.Host != test.host {
			t.Errorf("Test %d (%s): Expected host '%s', got '%s'", i, test.input, test.host, actual.Host)
		}
		if actual.Port != test.port {
			t.Errorf("Test %d (%s): Expected port '%s', got '%s'", i, test.input, test.port, actual.Port)
		}
		if actual.Path != test.path {
			t.Errorf("Test %d (%s): Expected path '%s', got '%s'", i, test.input, test.path, actual.Path)
		}
	}
}

func TestAddressString(t *testing.T) {
	for i, test := range []struct {
		addr     Address
		expected string
	}{
		{Address{Scheme: "http", Host: "host", Port: "1234", Path: "/path"}, "http://host:1234/path"},
		{Address{Scheme: "", Host: "host", Port: "", Path: ""}, "http://host"},
		{Address{Scheme: "", Host: "host", Port: "80", Path: ""}, "http://host"},
		{Address{Scheme: "", Host: "host", Port: "443", Path: ""}, "https://host"},
		{Address{Scheme: "https", Host: "host", Port: "443", Path: ""}, "https://host"},
		{Address{Scheme: "https", Host: "host", Port: "", Path: ""}, "https://host"},
		{Address{Scheme: "", Host: "host", Port: "80", Path: "/path"}, "http://host/path"},
		{Address{Scheme: "http", Host: "", Port: "1234", Path: ""}, "http://:1234"},
		{Address{Scheme: "", Host: "", Port: "", Path: ""}, ""},
	} {
		actual := test.addr.String()
		if actual != test.expected {
			t.Errorf("Test %d: expected '%s' but got '%s'", i, test.expected, actual)
		}
	}
}

func TestKeyNormalization(t *testing.T) {
	testCases := []struct {
		input  string
		expect string
	}{
		{
			input:  "http://host:1234/path",
			expect: "http://host:1234/path",
		},
		{
			input:  "HTTP://A/ABCDEF",
			expect: "http://a/ABCDEF",
		},
		{
			input:  "A/ABCDEF",
			expect: "a/ABCDEF",
		},
		{
			input:  "A:2015/Path",
			expect: "a:2015/Path",
		},
		{
			input:  ":80",
			expect: ":80",
		},
		{
			input:  ":443",
			expect: ":443",
		},
		{
			input:  ":1234",
			expect: ":1234",
		},
		{
			input:  "",
			expect: "",
		},
		{
			input:  ":",
			expect: "",
		},
		{
			input:  "[::]",
			expect: "::",
		},
	}
	for i, tc := range testCases {
		addr, err := ParseAddress(tc.input)
		if err != nil {
			t.Errorf("Test %d: Parsing address '%s': %v", i, tc.input, err)
			continue
		}
		expect := tc.expect
		if !caseSensitivePath {
			// every other part of the address should be lowercased when normalized,
			// so simply lower-case the whole thing to do case-insensitive comparison
			// of the path as well
			expect = strings.ToLower(expect)
		}
		if actual := addr.Normalize().Key(); actual != expect {
			t.Errorf("Test %d: Normalized key for address '%s' was '%s' but expected '%s'", i, tc.input, actual, expect)
		}

	}
}
