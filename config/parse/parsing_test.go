package parse

import "testing"

func TestStandardAddress(t *testing.T) {
	for i, test := range []struct {
		input      string
		host, port string
		shouldErr  bool
	}{
		{`localhost`, "localhost", "", false},
		{`localhost:1234`, "localhost", "1234", false},
		{`localhost:`, "localhost", "", false},
		{`0.0.0.0`, "0.0.0.0", "", false},
		{`127.0.0.1:1234`, "127.0.0.1", "1234", false},
		{`:1234`, "", "1234", false},
		{`[::1]`, "::1", "", false},
		{`[::1]:1234`, "::1", "1234", false},
		{`:`, "", "", false},
		{`localhost:http`, "localhost", "http", false},
		{`localhost:https`, "localhost", "https", false},
		{`:http`, "", "http", false},
		{`:https`, "", "https", false},
		{`http://localhost`, "localhost", "http", false},
		{`https://localhost`, "localhost", "https", false},
		{`http://127.0.0.1`, "127.0.0.1", "http", false},
		{`https://127.0.0.1`, "127.0.0.1", "https", false},
		{`http://[::1]`, "::1", "http", false},
		{`http://localhost:1234`, "localhost", "1234", false},
		{`https://127.0.0.1:1234`, "127.0.0.1", "1234", false},
		{`http://[::1]:1234`, "::1", "1234", false},
		{``, "", "", false},
		{`::1`, "::1", "", true},
		{`localhost::`, "localhost::", "", true},
		{`#$%@`, "#$%@", "", true},
	} {
		host, port, err := standardAddress(test.input)

		if err != nil && !test.shouldErr {
			t.Errorf("Test %d: Expected no error, but had error: %v", i, err)
		}
		if err == nil && test.shouldErr {
			t.Errorf("Test %d: Expected error, but had none", i)
		}

		if host != test.host {
			t.Errorf("Test %d: Expected host '%s', got '%s'", i, test.host, host)
		}

		if port != test.port {
			t.Errorf("Test %d: Expected port '%s', got '%s'", i, test.port, port)
		}
	}
}
