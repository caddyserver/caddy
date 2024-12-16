package httpcaddyfile

import (
	"testing"
)

func TestParseAddress(t *testing.T) {
	for i, test := range []struct {
		input                    string
		scheme, host, port, path string
		shouldErr                bool
	}{
		{``, "", "", "", "", false},
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
		{`http://localhost:443`, "http", "localhost", "443", "", false}, // NOTE: not conventional
		{`https://localhost:80`, "https", "localhost", "80", "", false}, // NOTE: not conventional
		{`http://localhost`, "http", "localhost", "", "", false},
		{`https://localhost`, "https", "localhost", "", "", false},
		{`http://{env.APP_DOMAIN}`, "http", "{env.APP_DOMAIN}", "", "", false},
		{`{env.APP_DOMAIN}:80`, "", "{env.APP_DOMAIN}", "80", "", false},
		{`{env.APP_DOMAIN}/path`, "", "{env.APP_DOMAIN}", "", "/path", false},
		{`example.com/{env.APP_PATH}`, "", "example.com", "", "/{env.APP_PATH}", false},
		{`http://127.0.0.1`, "http", "127.0.0.1", "", "", false},
		{`https://127.0.0.1`, "https", "127.0.0.1", "", "", false},
		{`http://[::1]`, "http", "::1", "", "", false},
		{`http://localhost:1234`, "http", "localhost", "1234", "", false},
		{`https://127.0.0.1:1234`, "https", "127.0.0.1", "1234", "", false},
		{`http://[::1]:1234`, "http", "::1", "1234", "", false},
		{``, "", "", "", "", false},
		{`::1`, "", "::1", "", "", false},
		{`localhost::`, "", "localhost::", "", "", false},
		{`#$%@`, "", "#$%@", "", "", false}, // don't want to presume what the hostname could be
		{`host/path`, "", "host", "", "/path", false},
		{`http://host/`, "http", "host", "", "/", false},
		{`//asdf`, "", "", "", "//asdf", false},
		{`:1234/asdf`, "", "", "1234", "/asdf", false},
		{`http://host/path`, "http", "host", "", "/path", false},
		{`https://host:443/path/foo`, "https", "host", "443", "/path/foo", false},
		{`host:80/path`, "", "host", "80", "/path", false},
		{`/path`, "", "", "", "/path", false},
	} {
		actual, err := ParseAddress(test.input)

		if err != nil && !test.shouldErr {
			t.Errorf("Test %d (%s): Expected no error, but had error: %v", i, test.input, err)
		}
		if err == nil && test.shouldErr {
			t.Errorf("Test %d (%s): Expected error, but had none (%#v)", i, test.input, actual)
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
		expect Address
	}{
		{
			input: "example.com",
			expect: Address{
				Host: "example.com",
			},
		},
		{
			input: "http://host:1234/path",
			expect: Address{
				Scheme: "http",
				Host:   "host",
				Port:   "1234",
				Path:   "/path",
			},
		},
		{
			input: "HTTP://A/ABCDEF",
			expect: Address{
				Scheme: "http",
				Host:   "a",
				Path:   "/ABCDEF",
			},
		},
		{
			input: "A/ABCDEF",
			expect: Address{
				Host: "a",
				Path: "/ABCDEF",
			},
		},
		{
			input: "A:2015/Path",
			expect: Address{
				Host: "a",
				Port: "2015",
				Path: "/Path",
			},
		},
		{
			input: "sub.{env.MY_DOMAIN}",
			expect: Address{
				Host: "sub.{env.MY_DOMAIN}",
			},
		},
		{
			input: "sub.ExAmPle",
			expect: Address{
				Host: "sub.example",
			},
		},
		{
			input: "sub.\\{env.MY_DOMAIN\\}",
			expect: Address{
				Host: "sub.\\{env.my_domain\\}",
			},
		},
		{
			input: "sub.{env.MY_DOMAIN}.com",
			expect: Address{
				Host: "sub.{env.MY_DOMAIN}.com",
			},
		},
		{
			input: ":80",
			expect: Address{
				Port: "80",
			},
		},
		{
			input: ":443",
			expect: Address{
				Port: "443",
			},
		},
		{
			input: ":1234",
			expect: Address{
				Port: "1234",
			},
		},
		{
			input:  "",
			expect: Address{},
		},
		{
			input:  ":",
			expect: Address{},
		},
		{
			input: "[::]",
			expect: Address{
				Host: "::",
			},
		},
		{
			input: "127.0.0.1",
			expect: Address{
				Host: "127.0.0.1",
			},
		},
		{
			input: "[2001:db8:85a3:8d3:1319:8a2e:370:7348]:1234",
			expect: Address{
				Host: "2001:db8:85a3:8d3:1319:8a2e:370:7348",
				Port: "1234",
			},
		},
		{
			// IPv4 address in IPv6 form (#4381)
			input: "[::ffff:cff4:e77d]:1234",
			expect: Address{
				Host: "::ffff:cff4:e77d",
				Port: "1234",
			},
		},
		{
			input: "::ffff:cff4:e77d",
			expect: Address{
				Host: "::ffff:cff4:e77d",
			},
		},
	}
	for i, tc := range testCases {
		addr, err := ParseAddress(tc.input)
		if err != nil {
			t.Errorf("Test %d: Parsing address '%s': %v", i, tc.input, err)
			continue
		}
		actual := addr.Normalize()
		if actual.Scheme != tc.expect.Scheme {
			t.Errorf("Test %d: Input '%s': Expected Scheme='%s' but got Scheme='%s'", i, tc.input, tc.expect.Scheme, actual.Scheme)
		}
		if actual.Host != tc.expect.Host {
			t.Errorf("Test %d: Input '%s': Expected Host='%s' but got Host='%s'", i, tc.input, tc.expect.Host, actual.Host)
		}
		if actual.Port != tc.expect.Port {
			t.Errorf("Test %d: Input '%s': Expected Port='%s' but got Port='%s'", i, tc.input, tc.expect.Port, actual.Port)
		}
		if actual.Path != tc.expect.Path {
			t.Errorf("Test %d: Input '%s': Expected Path='%s' but got Path='%s'", i, tc.input, tc.expect.Path, actual.Path)
		}
	}
}
