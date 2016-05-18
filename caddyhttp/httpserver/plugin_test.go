package httpserver

import "testing"

func TestStandardizeAddress(t *testing.T) {
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
		{`localhost:http`, "http", "localhost", "80", "", false},
		{`localhost:https`, "https", "localhost", "443", "", false},
		{`:http`, "http", "", "80", "", false},
		{`:https`, "https", "", "443", "", false},
		{`http://localhost:https`, "", "", "", "", true}, // conflict
		{`http://localhost:http`, "", "", "", "", true},  // repeated scheme
		{`http://localhost:443`, "", "", "", "", true},   // not conventional
		{`https://localhost:80`, "", "", "", "", true},   // not conventional
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
		{`host:https/path`, "https", "host", "443", "/path", false},
	} {
		actual, err := standardizeAddress(test.input)

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

func TestAddressVHost(t *testing.T) {
	for i, test := range []struct {
		addr     Address
		expected string
	}{
		{Address{Original: "host:1234"}, "host:1234"},
		{Address{Original: "host:1234/foo"}, "host:1234/foo"},
		{Address{Original: "host/foo"}, "host/foo"},
		{Address{Original: "http://host/foo"}, "host/foo"},
		{Address{Original: "https://host/foo"}, "host/foo"},
	} {
		actual := test.addr.VHost()
		if actual != test.expected {
			t.Errorf("Test %d: expected '%s' but got '%s'", i, test.expected, actual)
		}
	}
}
