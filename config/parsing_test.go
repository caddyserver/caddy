package config

import "testing"

func TestParseAddress(t *testing.T) {
	type addr struct {
		host string
		port string
	}
	testCases := []struct {
		input    string
		expected addr
	}{
		{input: "host:port", expected: addr{host: "host", port: "port"}},
		{input: "localhost:1234", expected: addr{host: "localhost", port: "1234"}},
		{input: "127.0.0.1:0", expected: addr{host: "127.0.0.1", port: "0"}},
		{input: "127.0.0.1", expected: addr{host: "127.0.0.1", port: ""}},
		{input: "somedomain.com", expected: addr{host: "somedomain.com", port: ""}},
		{input: "somedomain.com:", expected: addr{host: "somedomain.com", port: ""}},
		{input: ":80", expected: addr{host: "", port: "80"}},
		{input: "localhost:8080", expected: addr{host: "localhost", port: "8080"}},
		{input: "", expected: addr{host: "", port: ""}},
	}
	for _, test := range testCases {
		actualHost, actualPort := parseAddress(test.input)
		if actualHost != test.expected.host {
			t.Errorf("For '%s' expected host '%s' but got '%s'", test.input, test.expected.host, actualHost)
		}
		if actualPort != test.expected.port {
			t.Errorf("For '%s' expected port '%s' but got '%s'", test.input, test.expected.port, actualPort)
		}
	}
}
